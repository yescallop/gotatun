// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use x25519_dalek::PublicKey;

use crate::packet::{Ip, Packet};
use crate::tun::MtuWatcher;

/// What to do with a packet, as decided by a [`Router`].
pub enum Verdict {
    /// Write the packet to the TUN device.
    ToTun(Packet<Ip>),
    /// Encapsulate the packet and send it to the peer with this public key.
    ToPeer(PublicKey, Packet<Ip>),
    /// Nothing more to do: the router has kept or dropped the packet.
    Consumed,
}

/// Decides where packets go, in place of routing them by allowed IPs.
///
/// With a router set, a [`Device`] no longer looks at a [`Peer`]'s allowed IPs. It accepts whatever
/// source address a peer sends, and leaves any checks to the router. The verdict need not concern
/// the packet given: a router can replace it, for example with an ICMP error about it.
///
/// A packet for a peer with no session starts a handshake, and is dropped rather than queued for
/// when it completes, however long that takes, so that a late packet can't surprise a router's
/// protocols.
///
/// Both methods are called on the device's packet-processing tasks, once per packet, so they should
/// return quickly, and must not block.
///
/// [`Device`]: crate::device::Device
/// [`Peer`]: crate::device::Peer
pub trait Router: Send + Sync + 'static {
    /// Routes a packet decrypted from the peer with public key `from`. It may carry padding after
    /// the end of the IP packet.
    ///
    /// `mtu` is the MTU of the TUN device.
    fn route_from_peer(
        &self,
        from: &PublicKey,
        packet: Packet<Ip>,
        mtu: &mut MtuWatcher,
    ) -> Verdict;

    /// Routes a packet read from the TUN device.
    fn route_from_tun(&self, packet: Packet<Ip>) -> Verdict;
}
