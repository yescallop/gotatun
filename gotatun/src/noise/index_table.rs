// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

use std::any::Any;
use std::collections::HashMap;
use std::collections::hash_map;
use std::sync::{Arc, Weak};

use parking_lot::{Mutex, RwLock};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

use crate::noise::session::Session;

/// A table mapping session IDs to what they identify.
///
/// All peers share a single `IndexTable` to ensure no two sessions use the same index.
/// Indices are random `u32`s and freed automatically when the returned [`Index`] is dropped.
///
/// This mirrors the Linux kernel's `index_hashtable`: an entry is created when a
/// handshake reserves an index, is upgraded in place to point at the session that
/// handshake produces (the kernel's `wg_index_hashtable_replace`), and is removed by
/// the owner's destructor rather than by any periodic sweep.
pub struct IndexTable<Rng = StdRng>(Arc<Inner<Rng>>);

struct Inner<Rng> {
    /// Only touched when minting a new index.
    rng: Mutex<Rng>,
    map: RwLock<HashMap<u32, Entry>>,
}

/// A handle to whatever owns a set of indices — in practice a peer.
///
/// The noise layer never looks inside it; it only carries it back out again, so
/// the concrete peer type stays a device-layer concern. This is the kernel's
/// `struct wg_peer *peer` field on `index_hashtable_entry`, type-erased because
/// `Index` lives beneath the layer that defines a peer.
pub type Owner = Weak<dyn Any + Send + Sync>;

/// What an index currently identifies.
///
/// `session: None` is the kernel's `INDEX_HASHTABLE_HANDSHAKE`; `Some` is
/// `INDEX_HASHTABLE_KEYPAIR`. Keeping them in one table lets a lookup reject a
/// data packet that names a handshake, and vice versa.
struct Entry {
    owner: Option<Owner>,
    session: Option<Weak<Session>>,
}

impl<Rng> Clone for IndexTable<Rng> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

/// A 32-bit index that locally represents the other peer, analogous to IPsec’s “SPI”.
///
/// A session index is derived from [`IndexTable::new_index`], and the session index is
/// automatically freed from its [`IndexTable`] on drop.
///
/// See section 5.4 of the [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
pub struct Index<Rng = StdRng> {
    value: u32,
    table: IndexTable<Rng>,
}

impl<Rng> IndexTable<Rng>
where
    Rng: RngCore,
{
    /// Generate a random `u32` not already in the table.
    ///
    /// The returned [`Index`] keeps the entry reserved; dropping it frees the slot.
    pub fn new_index(&self) -> Index<Rng> {
        self.new_index_owned(None)
    }

    /// Generate a random `u32` not already in the table, attributed to `owner`.
    ///
    /// A lookup on the resulting index hands `owner` back, so the caller that
    /// resolves a packet learns which peer it belongs to without a second map.
    pub fn new_index_owned(&self, owner: Option<Owner>) -> Index<Rng> {
        // Find a free index by guessing. See the rationale here:
        // https://github.com/torvalds/linux/blob/e81dd54f62c753dd423d1a9b62481a1c599fb975/drivers/net/wireguard/peerlookup.c#L95-L117
        // Even if the table contained 2^31 entries, you'd usually only need 1-2 attempts.
        loop {
            let idx = Self::next_id(&mut self.0.rng.lock());
            // The index is only ours once it is in the map, so a racing minter
            // that guessed the same value makes us guess again.
            if let hash_map::Entry::Vacant(slot) = self.0.map.write().entry(idx) {
                slot.insert(Entry {
                    owner: owner.clone(),
                    session: None,
                });
                return Index {
                    value: idx,
                    table: Self(Arc::clone(&self.0)),
                };
            }
        }
    }

    /// Naively generate the next session ID. This index is not guaranteed to be locally unique.
    pub(crate) fn next_id(rng: &mut Rng) -> u32 {
        rng.next_u32()
    }

    /// Create a new [`IndexTable`] using the given [`RngCore`].
    pub fn from_rng(rng: Rng) -> Self {
        IndexTable(Arc::new(Inner {
            rng: Mutex::new(rng),
            map: RwLock::new(HashMap::new()),
        }))
    }

    /// Check if an index is already in the table.
    pub fn in_use(&self, value: u32) -> bool {
        self.0.map.read().contains_key(&value)
    }
}

impl<Rng> IndexTable<Rng>
where
    Rng: SeedableRng + RngCore,
{
    /// Create a new [`IndexTable`] seeded using [`SeedableRng::from_os_rng`].
    pub fn from_os_rng() -> Self {
        Self::from_rng(Rng::from_os_rng())
    }
}

impl<Rng> IndexTable<Rng> {
    /// Remove an index from the table, making it available for reuse.
    ///
    /// The removed [`Entry`] holds only weak references, so dropping it under the
    /// write lock cannot run a destructor that reaches back into the table.
    fn free_index(&self, index: u32) {
        self.0.map.write().remove(&index);
    }

    /// Resolve an index to the session that owns it.
    ///
    /// Returns `None` if the index is unknown, still identifies an in-flight
    /// handshake rather than a session, or names a session that has since been
    /// dropped. This is the kernel's `wg_index_hashtable_lookup` with an
    /// `INDEX_HASHTABLE_KEYPAIR` type mask.
    pub fn lookup_session(&self, index: u32) -> Option<Arc<Session>> {
        // Upgrade with the lock released. See `lookup_session_and_owner`.
        let session = self.0.map.read().get(&index)?.session.clone()?;
        session.upgrade()
    }

    /// Resolve an index to its session and the peer that owns it, in one lookup.
    ///
    /// This is the whole point of giving the table a value: a data packet names an
    /// index, and this yields everything needed to decrypt it and to account for it
    /// afterwards, exactly as `wg_index_hashtable_lookup` fills in its `peer`
    /// out-parameter alongside the returned keypair.
    pub fn lookup_session_and_owner(
        &self,
        index: u32,
    ) -> Option<(Arc<Session>, Arc<dyn Any + Send + Sync>)> {
        // Take weak references out under the lock and upgrade them without it.
        //
        // Both upgrades can yield a strong reference whose destructor takes the
        // *write* lock: the last `Arc<Session>` frees its index, and the last owner
        // is a peer that drops the sessions it holds. Letting either fall out of
        // scope — which the `?` below does whenever the other upgrade fails — while
        // this thread still held the read guard would deadlock against itself.
        let (session, owner) = {
            let map = self.0.map.read();
            let entry = map.get(&index)?;
            (entry.session.clone()?, entry.owner.clone()?)
        };
        Some((session.upgrade()?, owner.upgrade()?))
    }

    /// Resolve an index that identifies an *in-flight handshake* to its peer.
    ///
    /// Returns `None` once the index has been carried over into a session, so a
    /// handshake response cannot be answered with an established session's index.
    /// This is the `INDEX_HASHTABLE_HANDSHAKE` half of the kernel's type mask.
    pub fn lookup_handshake_owner(&self, index: u32) -> Option<Arc<dyn Any + Send + Sync>> {
        let owner = {
            let map = self.0.map.read();
            let entry = map.get(&index)?;
            if entry.session.is_some() {
                return None;
            }
            entry.owner.clone()?
        };
        // Upgrade with the lock released. See `lookup_session_and_owner`.
        owner.upgrade()
    }

    /// Resolve an index to its peer, whatever the index currently identifies.
    ///
    /// This is the kernel's `INDEX_HASHTABLE_HANDSHAKE | INDEX_HASHTABLE_KEYPAIR`
    /// mask, which cookie replies are looked up under. A cookie reply answers a
    /// handshake message we sent, but the handshake it names may already have
    /// completed by the time it arrives — and the cookie is still worth keeping for
    /// the next initiation we send, so the entry's type must not gate it.
    pub fn lookup_owner(&self, index: u32) -> Option<Arc<dyn Any + Send + Sync>> {
        // Upgrade with the lock released. See `lookup_session_and_owner`.
        let owner = self.0.map.read().get(&index)?.owner.clone()?;
        owner.upgrade()
    }
}

impl<Rng> Index<Rng> {
    /// Point this index at the session it now identifies.
    ///
    /// The index is reserved by the handshake and carried over into the session it
    /// produces, so this upgrades the existing entry in place rather than allocating
    /// a new one — the same handover the kernel performs in
    /// `wg_index_hashtable_replace`, where `new->index = old->index`.
    ///
    /// `session` must be the session that owns this very `Index`, so that dropping
    /// the session removes the entry.
    pub(super) fn register_session(&self, session: &Arc<Session>) {
        let mut map = self.table.0.map.write();
        // Silently failing here would leave the session unreachable by its index,
        // which looks like a dead tunnel rather than a bug. The kernel reports the
        // same condition through `wg_index_hashtable_replace`'s return value.
        let entry = map
            .get_mut(&self.value)
            .expect("an `Index` holds its own entry until it is dropped");
        entry.session = Some(Arc::downgrade(session));
    }
}

impl Index {
    /// The raw `u32` index value.
    pub fn value(&self) -> u32 {
        self.value
    }
}

impl<Rng> Drop for Index<Rng> {
    fn drop(&mut self) {
        self.table.free_index(self.value);
    }
}

impl std::fmt::Debug for Index {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f)
    }
}

impl std::fmt::Display for Index {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct ModCounter {
        dividend: u32,
        divisor: u32,
    }

    impl RngCore for ModCounter {
        fn next_u32(&mut self) -> u32 {
            let v = self.dividend % self.divisor;
            self.dividend += 1;
            v
        }

        fn next_u64(&mut self) -> u64 {
            unimplemented!()
        }

        fn fill_bytes(&mut self, _: &mut [u8]) {
            unimplemented!()
        }
    }

    /// Test that indices are freed when dropped.
    #[test]
    fn test_reuse_on_drop() {
        let table = IndexTable::from_rng(ModCounter {
            dividend: 0,
            divisor: 3,
        });

        let a = table.new_index();
        let b = table.new_index();
        let c = table.new_index();

        assert_eq!(a.value, 0);
        assert_eq!(b.value, 1);
        assert_eq!(c.value, 2);

        // 1 should be the only free value
        let recycled = b.value;
        drop(b);
        for _ in 0..10 {
            assert_eq!(table.new_index().value, recycled);
        }
    }

    /// An entry's type gates which lookups may answer with it, as the kernel's
    /// `INDEX_HASHTABLE_HANDSHAKE` / `INDEX_HASHTABLE_KEYPAIR` mask does.
    #[test]
    fn lookups_respect_the_entry_type() {
        let table: IndexTable = IndexTable::from_os_rng();
        let owner: Arc<dyn Any + Send + Sync> = Arc::new(());
        let index = table.new_index_owned(Some(Arc::downgrade(&owner)));
        let value = index.value();

        // While the index only reserves a handshake, a data packet must not
        // resolve to it, but a handshake response must.
        assert!(table.lookup_session(value).is_none());
        assert!(table.lookup_handshake_owner(value).is_some());
        assert!(table.lookup_owner(value).is_some());

        let session = Arc::new(Session::new(index, 0, [0u8; 32], [0u8; 32]));
        session.receiving_index.register_session(&session);

        // Once it names the session that handshake produced, the two swap over. A
        // cookie reply resolves either way, since it may be answering a handshake
        // that completed while the reply was in flight.
        assert!(table.lookup_session(value).is_some());
        assert!(table.lookup_handshake_owner(value).is_none());
        assert!(table.lookup_owner(value).is_some());

        // The session owns the index, so dropping it frees the entry outright.
        drop(session);
        assert!(!table.in_use(value));
        assert!(table.lookup_owner(value).is_none());
    }

    /// A lookup on an index whose peer is gone must still resolve cleanly.
    ///
    /// This is the single-threaded shadow of the deadlock `lookup_session_and_owner`
    /// guards against: the real race needs another thread to release the session
    /// between the two upgrades, which is why the guarantee lives in that function's
    /// structure — upgrading with the lock released — rather than in this test.
    #[test]
    fn lookup_tolerates_a_dropped_owner() {
        let table: IndexTable = IndexTable::from_os_rng();
        let owner: Arc<dyn Any + Send + Sync> = Arc::new(());
        let index = table.new_index_owned(Some(Arc::downgrade(&owner)));
        let value = index.value();

        let session = Arc::new(Session::new(index, 0, [0u8; 32], [0u8; 32]));
        session.receiving_index.register_session(&session);

        drop(owner);
        assert!(table.lookup_session_and_owner(value).is_none());
        // The session outlives its peer, so the data lookup that needs no owner
        // still answers.
        assert!(table.lookup_session(value).is_some());
    }
}
