# Changelog — goodnet-link-quic

All notable changes to this plugin are listed here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions track the kernel ABI through `gn_link_vtable_t` and the
composer surface in `docs/contracts/link.en.md` §8.

## [Unreleased]

### Backpressure SOFT / CLEAR through the composer session

`ComposerSession::do_send` now enforces a
`pending_queue_bytes_hard` cap and publishes
`notify_backpressure` SOFT / CLEAR transitions through the link
host API. The kernel's QoS layer sees the QUIC link saturate
and de-saturate on the same channel as every other link, so
upper layers can throttle without polling stream-level state.

### Apache-2.0 LICENSE

Apache-2.0 LICENSE file added to the repository root. Matches
the OpenSSL-tied licensing already used by `link-tls`.

## [1.0.0-rc1] — 2026-05-12

Initial release of the QUIC transport plugin.

### Added

- OpenSSL-3.6-native QUIC connection driven by a memory
  `BIO_pair`. Each connection lives in a `ComposerSession`
  that wraps an `SSL*` and lets the carrier own the UDP wire.
- Composer pattern over a `LinkCarrier(udp)` per
  `docs/contracts/link.en.md` §8: the QUIC link does not bind
  its own UDP socket, it consumes the carrier's
  `notify_inbound_bytes`. Capability bits:
  `Stream | Reliable | Ordered | EncryptedPath`.
- Carrier dispatch in `resolve_carrier`. `quic://<64-hex>`
  routes through `IceCarrierBridge` for peer-key addressing
  over ICE-traversed UDP; any other `quic://host:port` falls
  back to the direct UDP carrier.
- Per-stream `SSL*` via `SSL_new_stream` /
  `SSL_accept_stream` hang off the parent connection. App data
  surfaces to the upper composer through the parent conn id;
  multiplexed first-class streams are a planned extension.
