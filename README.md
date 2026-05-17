# goodnet-link-quic

QUIC transport for GoodNet. OpenSSL-3.6-native QUIC layered on a
`LinkCarrier(udp)` per `docs/contracts/link.en.md` §8 composer pattern.
Maps `quic://<peer-pk-hex>` URIs (resolved through ICE) and
`quic://host:port` URIs (direct UDP) to a per-connection QUIC
session. Provides `Stream | Reliable | Ordered | EncryptedPath` on
top of whatever UDP carrier sits underneath — including the
NAT-traversed UDP that ICE produces.

Each connection-level QUIC handshake lives in a `ComposerSession`
that wraps an OpenSSL `SSL*` driven by a memory `BIO_pair`; the
carrier owns the wire. Per-stream `SSL*` objects (via
`SSL_new_stream` / `SSL_accept_stream`) hang off the connection but
expose application data to the upper composer through the parent
conn id — first-class stream multiplexing is a planned extension.

**Kind**: link · **Artefact**: dynamic plugin (`.so` via dlopen)
· **License**: Apache-2.0 (OpenSSL-tied, same as `link-tls`)

## Build

This plugin lives in its own git with a flake that pulls the
kernel SDK as a Nix input (OpenSSL ≥ 3.6 with QUIC support on the
build path). From this checkout:

```sh
nix run .#build         # release build of libgoodnet_link_quic.so
nix run .#test          # vanilla ctest
nix run .#test-asan     # AddressSanitizer + UBSan
nix run .#test-tsan     # ThreadSanitizer
```

The kernel monorepo also builds this plugin in-tree through its
own `nix run .#build -- release` — operator install consumes
every bundled `.so` from there.

## Load

Manifest entry pins the SHA-256 digest; `gn_plugin_init` registers
the `quic` scheme. See `docs/install.en.md` and
`docs/contracts/plugin-manifest.en.md` in the kernel tree.

## Carrier-dispatch

`quic://<64-hex>` routes through `IceCarrierBridge` (peer-key
addressing through ICE); any other `quic://host:port` falls back to
the direct UDP carrier. The detect logic lives in
`quic.cpp::resolve_carrier` and is depicted in
`docs/img/quic_carrier_dispatch.svg`.

## Contract

- Kernel-side link contract: `docs/contracts/link.en.md`
- Composer pattern: `docs/contracts/link.en.md` §8
- Capability bits the QUIC link exports:
  `Stream | Reliable | Ordered | EncryptedPath`
