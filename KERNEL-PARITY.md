# Parity with the Linux kernel WireGuard implementation

GotaTun implements the same protocol as `drivers/net/wireguard`, but as a userspace
library with a different concurrency model. This document records where the two agree,
where they deliberately differ, and where GotaTun is weaker and could be improved.

It is a design comparison, not a security audit — for those see [audits](./audits/README.md).

> **Provenance.** This document was written by Claude (an AI assistant) by reading both
> code bases, and has not been reviewed or verified by anyone else. Treat every claim in
> it as a starting point for your own reading, not as an established fact: the kernel
> references are pinned and can be followed, and the GotaTun claims can be checked against
> the files named. Nothing here is a security assurance, and an omission from the gaps
> below is not evidence that no gap exists.

Compared against Linux
[`bc35965f6940a9bf834d54187b6088b8eb09206d`](https://github.com/torvalds/linux/tree/bc35965f6940a9bf834d54187b6088b8eb09206d/drivers/net/wireguard).
All kernel line references below are pinned to that revision.

## Summary

The protocol core is faithful. Handshake construction and consumption, the replay
window, the session lifecycle, the timer state machine, and index lookup all match the
kernel's behaviour, and in several places match its structure as well.

The remaining gaps are concentrated in two areas: **hardening against handshake floods**,
where the kernel has three mechanisms GotaTun lacks, and **memory hygiene**, where
GotaTun does not zeroize key material at all. Neither affects correctness against a
well-behaved peer.

| Subsystem | Verdict |
| --- | --- |
| Noise handshake (IK, mac1/mac2, cookie construction) | Faithful |
| TAI64N replay guard | Faithful |
| Session roles and promotion | Structurally identical |
| Receiver-index lookup | Structurally identical |
| Replay window | Correct; different window size, see below |
| Timer state machine | All six kernel timers present |
| Allowed IPs and reverse-path filtering | Equivalent |
| Handshake flood resistance | **Weaker**, three distinct gaps |
| Key-material zeroization | **Absent** |
| ECN and DSCP propagation | **Absent** |
| Session expiry enforcement | Coarser: timer tick, not per packet |
| Crypto parallelism | Weaker: one socket-draining task |

## Where the structures match

### Receiver-index lookup

[`IndexTable`](./gotatun/src/noise/index_table.rs) mirrors the kernel's
[`index_hashtable`](https://github.com/torvalds/linux/blob/bc35965f6940a9bf834d54187b6088b8eb09206d/drivers/net/wireguard/peerlookup.c).
An entry is created when a handshake reserves an index, upgraded in place to name the
session that handshake produces — the kernel's `wg_index_hashtable_replace`, where
`new->index = old->index` — and removed by `Index::drop`, which is `keypair_free_kref`
calling `wg_index_hashtable_remove`. Neither implementation needs a periodic sweep.

Each entry carries the peer it belongs to, as `index_hashtable_entry` carries its
`struct wg_peer *`, so a data packet resolves to both its session and its peer in one
lookup. GotaTun stores the peer type-erased (`Weak<dyn Any + Send + Sync>`) because
`Index` lives beneath the layer that defines what a peer is; the device downcasts it in
`peer_from_index_owner`. The alternative — a type parameter — would spread from
`IndexTable` through `Index`, `Session`, `Sessions`, `Handshake` and `Tunn`, and would
have to be instantiated with a type that transitively contains `Tunn` itself.

The lookups reproduce the kernel's type mask
([`peerlookup.h`](https://github.com/torvalds/linux/blob/bc35965f6940a9bf834d54187b6088b8eb09206d/drivers/net/wireguard/peerlookup.h#L39-L42)):

| Message | Kernel mask | GotaTun |
| --- | --- | --- |
| Data | `INDEX_HASHTABLE_KEYPAIR` | `lookup_session_and_owner` |
| Handshake response | `INDEX_HASHTABLE_HANDSHAKE` | `lookup_handshake_owner` |
| Cookie reply | `HANDSHAKE \| KEYPAIR` | `lookup_owner` |

A cookie reply matches either type because it answers a handshake message that may well
have completed while the reply was in flight
([`cookie.c:205-207`](https://github.com/torvalds/linux/blob/bc35965f6940a9bf834d54187b6088b8eb09206d/drivers/net/wireguard/cookie.c#L205-L207)).

### Session roles

`Sessions` in [`noise/mod.rs`](./gotatun/src/noise/mod.rs) is the kernel's
`struct noise_keypairs`: `previous`, `current`, `next`. `Tunn::add_session` follows
[`add_new_keypair`](https://github.com/torvalds/linux/blob/bc35965f6940a9bf834d54187b6088b8eb09206d/drivers/net/wireguard/noise.c#L198-L250)
branch for branch, including the initiator case where a pending `next` is demoted to
`previous` and the existing `current` is dropped.

`Tunn::received_with_session` is
[`wg_noise_received_with_keypair`](https://github.com/torvalds/linux/blob/bc35965f6940a9bf834d54187b6088b8eb09206d/drivers/net/wireguard/noise.c#L253-L289):
an identity comparison against `next`, promoting `next → current → previous` only on a
match. The kernel checks unlocked and re-checks under `keypair_update_lock`; GotaTun
needs one check because the whole function runs inside the peer's mutex.

Sessions are shared (`Arc`), so a decryption in flight keeps its session alive after the
tunnel has moved on, as the kernel's refcount on `struct noise_keypair` does.

### Replay window

[`ReceivingKeyCounterValidator`](./gotatun/src/noise/session.rs) and the kernel's
[`counter_validate`](https://github.com/torvalds/linux/blob/bc35965f6940a9bf834d54187b6088b8eb09206d/drivers/net/wireguard/receive.c#L295-L331)
both implement an 8192-bit RFC 6479 bitmap, but with different effective windows.

The kernel reserves `COUNTER_REDUNDANT_BITS` (one `unsigned long`) because it clears
whole words, giving `COUNTER_WINDOW_SIZE = 8192 - 64 = 8128`. GotaTun clears at exact bit
boundaries, so the acceptable range `[next - 8192, next - 1]` maps bijectively onto all
8192 slots, and the full window is usable. Both are sound; GotaTun's is 64 counters wider.

Note also that `REJECT_AFTER_MESSAGES` differs slightly: GotaTun uses the whitepaper's
`2^64 - 2^13 - 1`, the kernel uses `U64_MAX - COUNTER_WINDOW_SIZE - 1`. The two differ by
63 and both are unreachable.

## Gaps worth closing

Ranked by what they would actually buy.

### 1. No key material is zeroized

The kernel calls `memzero_explicit` on every intermediate key, chaining key, and hash on
every handshake path, in `handshake_zero` when clearing a handshake, and when freeing a
keypair.

GotaTun does none of this. `zeroize` is not a dependency; the only trace of the intent is
a `// TODO: zeroize` in [`device/peer.rs`](./gotatun/src/device/peer.rs). Every `temp`,
`key`, `chaining_key` and `hash` local in
[`noise/handshake.rs`](./gotatun/src/noise/handshake.rs) is a plain `[u8; 32]` left on the
stack; the derived session keys are copied into the AEAD and the originals abandoned; and
`HandshakeState`'s stored chaining key and hash are dropped without clearing. Only the
`x25519-dalek` secret types zeroize, because they do it themselves.

For a userspace implementation this is the most valuable gap to close: core dumps, swap,
and heap reuse are all key-recovery surfaces that the kernel implementation does not have
to the same degree.

**Fix:** add `zeroize`, wrap the handshake intermediates in `Zeroizing<[u8; 32]>`, and give
`HandshakeState` and `Session` a zeroizing `Drop`.

### 2. Handshake flood resistance is weaker, in three independent ways

#### (a) No per-peer cap on consumed initiations

`wg_noise_handshake_consume_initiation` computes
[`flood_attack`](https://github.com/torvalds/linux/blob/bc35965f6940a9bf834d54187b6088b8eb09206d/drivers/net/wireguard/noise.c#L634-L640)
and drops the packet if the last initiation was consumed less than `1s / 50` ago —
`INITIATIONS_PER_SECOND = 50`. Consuming an initiation costs two DH operations and
generating the response costs two more, so this bounds the most expensive thing a single
peer can make the responder do.

[`Handshake::receive_handshake_initialization`](./gotatun/src/noise/handshake.rs) checks
only the TAI64N timestamp. A peer sending initiations with monotonically increasing
timestamps is consumed at line rate.

#### (b) Rate limiting stops once mac2 is valid

`wg_cookie_validate_packet` reaches `VALID_MAC_WITH_COOKIE_BUT_RATELIMITED` and *still*
consults
[`wg_ratelimiter_allow`](https://github.com/torvalds/linux/blob/bc35965f6940a9bf834d54187b6088b8eb09206d/drivers/net/wireguard/cookie.c#L146-L150),
a 20 packets/second token bucket with a burst of 5, dropping silently if it fails.

[`RateLimiter::verify_handshake`](./gotatun/src/noise/rate_limiter.rs) returns
`Ok(handshake)` unconditionally once mac2 verifies. An attacker who solves one cookie
challenge — valid for up to `COOKIE_REFRESH` = 128 seconds — currently has an uncapped
initiation rate from that address.

#### (c) `under_load` is per-IP, so a distributed flood never triggers cookies

The kernel's under-load condition is device-global: handshake queue depth at or above
`MAX_QUEUED_INCOMING_HANDSHAKES / 8`, with one second of hysteresis
([`receive.c:113-121`](https://github.com/torvalds/linux/blob/bc35965f6940a9bf834d54187b6088b8eb09206d/drivers/net/wireguard/receive.c#L113-L121)).

[`RateLimiter::is_under_load`](./gotatun/src/noise/rate_limiter.rs) counts per source IP
against `HANDSHAKE_RATE_LIMIT` = 100 per second. A flood from ten thousand addresses at
100/s each puts the kernel into cookie mode and leaves GotaTun challenging nobody.

The per-IP design gives *better* isolation between well-behaved peers, and there is a test
for that behaviour, so the fix is to add a global condition alongside it rather than to
replace it.

Two smaller notes on the same code: the per-IP `HashMap` is unbounded within a one-second
window and mac1 is checkable by anyone who knows the server's public key, so spoofed
sources can grow it freely — the kernel's ratelimiter has `max_entries` and explicit
eviction. And clearing the map wholesale is a fixed window rather than a token bucket, so
`2 × limit` fits into a burst spanning the boundary.

### 3. No ECN or DSCP handling

The kernel copies the inner packet's DS field onto the outer header on encapsulation
(`ip_tunnel_ecn_encap`,
[`send.c:378`](https://github.com/torvalds/linux/blob/bc35965f6940a9bf834d54187b6088b8eb09206d/drivers/net/wireguard/send.c#L378)),
propagates congestion marks back inward on decapsulation per RFC 6040
(`INET_ECN_decapsulate`,
[`receive.c:389`](https://github.com/torvalds/linux/blob/bc35965f6940a9bf834d54187b6088b8eb09206d/drivers/net/wireguard/receive.c#L389)),
and sends handshakes marked `HANDSHAKE_DSCP` so they are prioritised under congestion.

GotaTun does none of this. The packet parsers expose the DSCP and ECN fields, but nothing
in [`src/udp/`](./gotatun/src/udp/) can set them and nothing in the noise or device path
reads them. The practical effect is that ECN signalling is destroyed by the tunnel, so
inner flows lose congestion feedback and fall back to loss-based control.

This is the most involved fix, requiring per-packet control messages on send and so
platform-specific work in the UDP layer.

### 4. Session expiry is enforced on the timer tick, not per packet

The kernel re-checks `receiving.is_valid`, birthdate expiry, and `REJECT_AFTER_MESSAGES`
inside `decrypt_packet` for **every** packet, latching `is_valid = false` on first failure
([`receive.c:252-256`](https://github.com/torvalds/linux/blob/bc35965f6940a9bf834d54187b6088b8eb09206d/drivers/net/wireguard/receive.c#L252-L256)).

GotaTun checks the packet's own counter against `REJECT_AFTER_MESSAGES` in
`Session::receive_packet_data`, but leaves birthdate expiry to `expire_old_sessions` on
the 250 ms timer tick. An expired session therefore keeps decrypting for up to 250 ms past
`REJECT_AFTER_TIME`.

Now that the birthdate lives on the `Session` rather than in an array beside it, moving
this check into `receive_packet_data` is small and self-contained.

### 5. Smaller items

- **`REKEY_AFTER_MESSAGES` is not implemented.** The kernel's `keep_key_fresh`
  ([`send.c:124-135`](https://github.com/torvalds/linux/blob/bc35965f6940a9bf834d54187b6088b8eb09206d/drivers/net/wireguard/send.c#L124-L135))
  rekeys after `2^60` messages as well as after `REKEY_AFTER_TIME`, and does so regardless
  of who initiated. GotaTun rekeys only on time, and only as initiator. Unreachable in
  practice — roughly 36,000 years at one million packets per second — and the 180 second
  expiry self-heals it, but it is a specified behaviour with no implementation.
- **TAI64N timestamps are not rounded.** The kernel truncates `tv_nsec` down to a power of
  two near `1s / INITIATIONS_PER_SECOND`, which both caps its own initiation rate and
  coarsens the clock it exposes. `TimeStamper::stamp` emits full nanosecond precision,
  a minor clock oracle available to anyone who can trigger a handshake.
- **One task drains the UDP socket.** The kernel has per-CPU encrypt and decrypt queues
  plus NAPI. Moving decryption off the peer mutex was the prerequisite for parallelism
  here, but realising it needs a worker pool, which reintroduces the TUN write-ordering
  problem the kernel solves with `wg_prev_queue_peek`.
- `ReceivingKeyCounterValidator::will_accept` returns `DuplicateCounter` where
  `mark_did_receive` returns `InvalidCounter` for the identical condition.

## Deliberate divergences

These differ from the kernel on purpose and are believed correct.

- **Two handshakes may be in flight.** `Handshake` keeps a `previous` state so a delayed
  response to an earlier initiation is still accepted on a bad network. The kernel has a
  single `noise_handshake` per peer. This doubles the window in which a stale response can
  establish a session and the number of indices reserved per peer.
- **Under-load is per-IP rather than device-global.** Better isolation between peers, worse
  against a distributed flood. See gap 2(c).
- **`timer_need_another_keepalive` is omitted.** The kernel arms a second keepalive if data
  arrives while one is already pending; GotaTun's single `want_keepalive` does not. Noted
  in a comment in [`noise/timers.rs`](./gotatun/src/noise/timers.rs).
- **Padding is clamped to the TUN MTU.** The kernel pads unconditionally to a multiple of
  16. GotaTun clamps so the result cannot exceed the MTU, matching `wireguard-go`.
- **Allowed IPs use a general-purpose LPM trie** (`ip_network_table`) rather than the
  kernel's hand-written radix trie. Functionally equivalent.
- **`Handshake::reset` preserves `last_handshake_timestamp`**, as the kernel's
  `handshake_zero` preserves `latest_timestamp`. Replay protection must survive a reset.

## Out of scope

DAITA has no kernel counterpart. The UAPI surface is compared against `wg(8)` rather than
against the kernel module; see [UAPI](./UAPI.md).
