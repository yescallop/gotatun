# Changes for cynet

This branch is upstream gotatun, at `2a867b3` (0.10.2), with changes made for
[cynet](https://github.com/yescallop/cynet). cynet builds a WireGuard mesh: it runs the Babel routing
protocol inside the tunnels and forwards packets between peers in userspace.

Allowed IPs can't express that. A forwarded packet's source usually belongs to some other node, so
the source check would drop it, and routes change as Babel learns them. So cynet decides where
packets go, and gotatun gains just enough to carry that out. Policy, such as source filters and ICMP
errors, stays in cynet.

A device with no router set behaves as upstream does, apart from the two fixes below.

## Routing by a `Router`

`DeviceBuilder::with_router` sets a `Router` ([device/router.rs](gotatun/src/device/router.rs)). It
is asked about each packet from a peer and each packet from the TUN, and answers with a `Verdict`:
`ToTun`, `ToPeer` or `Consumed`. The packet in the verdict need not be the one it was given, so an
ICMP error is just a new packet in an ordinary verdict.

With a router set, these differ from upstream:

| | Upstream | With a router |
|---|---|---|
| Source of a packet from a peer | Must route back to that peer by allowed IPs | Not checked |
| IPv4 packet with options from a peer | Dropped | Passed to the router |
| Packet from the TUN | Goes to the peer chosen by allowed IPs | Goes where the router says, which can be back to the TUN |
| Packet for a peer with no session | Queued, and a handshake started | Dropped, and a handshake started |
| Packet for a peer with no endpoint | Dropped and logged as an error | Dropped silently |

The reasons that aren't obvious:

- **Dropping rather than queueing.** Babel packets carry transmit timestamps. A Hello that waited in
  the queue for a handshake reached the neighbour late and out of order, which inflated its RTT
  samples. Babel sends again anyway. `Tunn::handle_outgoing_packet_unqueued` is what does this.
- **No error for a missing endpoint.** A router chooses the peer itself, and a peer that has yet to
  contact this node is no fault, so the log line would only be noise.
- **The sending peer's lock is released before the router is called.** A verdict can send the packet
  back to the same peer, which would otherwise deadlock on the lock.

## `Device::send_to_peer`

This encapsulates a packet and sends it straight on the UDP socket, rather than through the queue
that forwarded traffic shares. cynet sends Babel packets this way, so that their transmit timestamps
stay accurate and they don't wait behind data.

## Smaller changes

- `Device::wait` and `Device::stop` take `&self`, because cynet shares the device in an `Arc`. Stopping
  twice is harmless, as dropping a device stops it anyway. `gotatun-cli` lost a `mut` for it.
- `PeerState` holds the peer's public key, to tell the router who sent a packet.
- `DeviceState::encapsulate` is factored out of `handle_outgoing`, for all three ways of sending:
  packets from the TUN, forwarded packets, and `send_to_peer`.

## Fixes that aren't specific to cynet

These apply with or without a router, and could go upstream.

`rx_bytes` now counts a received data packet as it arrived, with its 32 bytes of header and tag.
`tx_bytes` already counted sent packets that way, while `rx_bytes` only counted the decrypted length.
On an idle link, one node's "sent" in `cynet show` looked about a third larger than the other's
"received", with no packet missing. Kernel WireGuard and wireguard-go keep the two comparable.

`Tunn::time_since_last_handshake` now outlives the sessions, which also shows in the UAPI's
`last_handshake_time_sec`. It used to return `None` once they were cleared, which happens when
handshake retries give up, about 2 minutes after a peer goes silent. So `cynet show` said `none` just
when it mattered how long the peer had been gone. Kernel WireGuard keeps the time too. It is now only
`None` if no session has ever been established.

## Tests

- [device/tests.rs](gotatun/src/device/tests.rs): the `router_*` tests and
  `send_to_peer_reaches_the_peer`, using `device_pair_with_routers` from
  [device/tests/mock.rs](gotatun/src/device/tests/mock.rs).
- [noise/mod.rs](gotatun/src/noise/mod.rs): `peers_agree_on_bytes_sent_and_received`,
  `no_time_since_a_handshake_that_never_completed` and `last_handshake_outlives_its_sessions`.
