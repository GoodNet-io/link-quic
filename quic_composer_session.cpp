// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/quic/quic_composer_session.cpp
/// @brief  QuicLink::ComposerSession — OpenSSL 3.6 native QUIC over a
///         datagram BIO pair. Listener-pattern on the server side per
///         the rework captured in Слайс 8b of the plan.

#include "quic_composer_session.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/quic.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <asio/bind_executor.hpp>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <utility>

namespace gn::link::quic {

namespace {

/// Synthetic 127.0.0.<last>:<port> BIO_ADDR for memory-pair loopback.
/// The actual IP is metadata — the dgram pair never touches the
/// network — but OpenSSL QUIC requires non-zero src/dst addresses to
/// build a (src,dst) connection key inside the listener.
BIO_ADDR* make_loopback_addr_v4(std::uint8_t last_octet,
                                  std::uint16_t port) {
    BIO_ADDR* addr = BIO_ADDR_new();
    if (!addr) return nullptr;
    std::uint32_t ip_bytes = (127U << 24) | (last_octet);
    struct in_addr ipv4;
    ipv4.s_addr = htonl(ip_bytes);
    if (BIO_ADDR_rawmake(addr, AF_INET, &ipv4, sizeof(ipv4),
                          htons(port)) != 1) {
        BIO_ADDR_free(addr);
        return nullptr;
    }
    return addr;
}

/// ALPN wire format: length-prefixed protocol IDs. GoodNet uses the
/// single token "gn-v1" so QUIC's mandatory ALPN check passes.
constexpr std::uint8_t kAlpnGnV1[] = {5, 'g', 'n', '-', 'v', '1'};

/// Fixed loopback addresses used as metadata on every datagram that
/// flows through the BIO_dgram_pair. The pair is per-session so the
/// same magic values are safe across simultaneous sessions — each
/// session's listener sees only its own peer's packets.
///
/// Routing invariant: client's `initial_peer_addr` must equal the
/// server's BIO local_addr (the listener routes incoming packets by
/// their dst tuple). Both sides therefore agree on `kServerLocal`;
/// the client uses `kClientLocal` for its own BIO halves.
constexpr std::uint16_t kServerPort = 443;
constexpr std::uint16_t kClientPort = 5000;
/// Both endpoints use the 127.0.0.1 loopback. Per QUIC path-validation
/// semantics the (local, peer) tuple must agree on the IP family;
/// putting client and server on different /8 subnets (127.0.0.1 vs
/// 127.0.0.2) breaks the implicit "same network" expectation.
constexpr std::uint8_t  kLoopbackOctet = 1;

}  // namespace

QuicLink::ComposerSession::ComposerSession(
    SSL_CTX*                ctx,
    Mode                    mode,
    gn_conn_id_t            l1_id,
    gn_conn_id_t            composer_id,
    std::weak_ptr<QuicLink> transport,
    asio::io_context&       ioc)
    : mode_(mode),
      l1_id_(l1_id),
      composer_id_(composer_id),
      transport_(std::move(transport)),
      strand_(asio::make_strand(ioc.get_executor())),
      tick_timer_(strand_) {
    /// Datagram-preserving BIO pair. Streaming `BIO_new_bio_pair`
    /// would coalesce QUIC packets and break the state machine —
    /// every BIO_read must yield exactly one record.
    if (BIO_new_bio_dgram_pair(&internal_bio_, 0, &network_bio_, 0) != 1) {
        return;
    }

    /// Both halves must claim they can handle DST + SRC addresses; the
    /// QUIC state machine refuses to operate over a BIO that drops
    /// per-datagram address metadata. Each half declares all four caps
    /// (HANDLES + PROVIDES, src + dst) — without `PROVIDES_*` the
    /// effective `local_addr_cap` of the OTHER half stays zero (the
    /// peer's cap query checks our PROVIDES bits) and `BIO_sendmmsg`
    /// rejects every msg with `local address not available`.
    const std::uint32_t kFullCaps =
        BIO_DGRAM_CAP_HANDLES_DST_ADDR |
        BIO_DGRAM_CAP_HANDLES_SRC_ADDR |
        BIO_DGRAM_CAP_PROVIDES_DST_ADDR |
        BIO_DGRAM_CAP_PROVIDES_SRC_ADDR;
    BIO_dgram_set_caps(internal_bio_, kFullCaps);
    BIO_dgram_set_caps(network_bio_,  kFullCaps);
    /// Capability ≠ enable. `BIO_dgram_set_caps` declares what the BIO
    /// *can* handle; `set_local_addr_enable` toggles whether `msg.local`
    /// is honoured on sendmmsg / surfaced on recvmmsg. QUIC drives both
    /// halves through `BIO_sendmmsg`/`BIO_recvmmsg` with the local-addr
    /// slot populated, so we flip the enable bit on both BIOs.
    (void)BIO_dgram_set_local_addr_enable(internal_bio_, 1);
    (void)BIO_dgram_set_local_addr_enable(network_bio_, 1);

    /// Synthetic loopback addresses. Server owns 127.0.0.1:443, client
    /// owns 127.0.0.1:5000; both endpoints share the 127.0.0.1 /32 so
    /// path validation accepts the (local, peer) tuple. Fixed values
    /// are safe because each session has its own private
    /// BIO_dgram_pair — different sessions never see each other's
    /// datagrams.
    const std::uint16_t my_port    = (mode_ == Mode::Server) ? kServerPort
                                                                : kClientPort;
    const std::uint16_t their_port = (mode_ == Mode::Server) ? kClientPort
                                                                : kServerPort;
    local_addr_ = make_loopback_addr_v4(kLoopbackOctet, my_port);
    peer_addr_  = make_loopback_addr_v4(kLoopbackOctet, their_port);
    if (local_addr_ && peer_addr_) {
        /// `internal_bio_` is what SSL reads/writes — its local addr =
        /// our own endpoint (so SSL's view of "where I am" matches the
        /// initial-peer-addr the other side targeted). `network_bio_`
        /// is what WE drive — when we BIO_sendmmsg into it the
        /// `msg.local` must match this BIO's local addr, so we pin it
        /// to the PEER's endpoint (the "source" the SSL on the other
        /// side will see). The pair routes the send across halves and
        /// the (peer, local) tuple SSL observes ends up as
        /// (peer = remote's local, local = our local).
        BIO_dgram_set0_local_addr(internal_bio_,
            make_loopback_addr_v4(kLoopbackOctet, my_port));
        BIO_dgram_set0_local_addr(network_bio_,
            make_loopback_addr_v4(kLoopbackOctet, their_port));
    }

    if (mode_ == Mode::Server) {
        /// Listener pattern: per-peer listener owns the BIO pair.
        /// `NO_VALIDATE` skips the RETRY-token round-trip; safe here
        /// because the carrier already authenticates the peer endpoint
        /// before composer_listen forwards the datagram.
        listener_ = SSL_new_listener(ctx, SSL_LISTENER_FLAG_NO_VALIDATE);
        if (listener_) {
            SSL_set_bio(listener_, internal_bio_, internal_bio_);
            SSL_set_blocking_mode(listener_, 0);
            SSL_listen(listener_);
        }
    } else {
        ssl_ = SSL_new(ctx);
        if (ssl_) {
            SSL_set_bio(ssl_, internal_bio_, internal_bio_);
            SSL_set_blocking_mode(ssl_, 0);
            /// Mandatory in QUIC. Client side wires the ALPN list now;
            /// the server's `alpn_select_cb` (registered on SSL_CTX)
            /// picks "gn-v1" out of this list.
            SSL_set_alpn_protos(ssl_, kAlpnGnV1, sizeof(kAlpnGnV1));
            SSL_set_connect_state(ssl_);
        }
    }
}

QuicLink::ComposerSession::~ComposerSession() {
    /// Per OpenSSL 3.6 docs (`SSL_accept_connection(3)`): the SSL*
    /// returned for an accepted server-side connection is reference
    /// counted, and the caller MUST `SSL_free` it independently of
    /// the listener. Without this, every accepted connection leaks
    /// its full handshake + transport state (~150 KB per session).
    /// Stream `SSL*` is owned by its parent connection — free it
    /// first so the cascade through the connection frees clean
    /// stream state, then free the connection, then the listener.
    if (stream_ssl_) {
        SSL_free(stream_ssl_);
        stream_ssl_ = nullptr;
    }
    if (ssl_) {
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    if (listener_) {
        SSL_free(listener_);
        listener_ = nullptr;
    }
    if (network_bio_) {
        BIO_free(network_bio_);
        network_bio_ = nullptr;
    }
    /// `internal_bio_` is owned by whichever SSL* was given it via
    /// SSL_set_bio — already freed above.
    if (local_addr_) {
        BIO_ADDR_free(local_addr_);
        local_addr_ = nullptr;
    }
    if (peer_addr_) {
        BIO_ADDR_free(peer_addr_);
        peer_addr_ = nullptr;
    }
}

SSL* QuicLink::ComposerSession::active_ssl_unlocked() const noexcept {
    if (ssl_) return ssl_;
    return listener_;
}

void QuicLink::ComposerSession::kick_client_handshake(
    std::string peer_uri) {
    std::lock_guard lk(mu_);
    peer_uri_ = std::move(peer_uri);
    if (!ssl_) return;
    /// Initial peer addr MUST equal the server's BIO local addr, or
    /// the listener's (local, peer) routing tuple rejects the
    /// ClientHello. `peer_addr_` was already pinned to
    /// 127.0.0.1:kServerPort in the ctor.
    if (peer_addr_) {
        SSL_set1_initial_peer_addr(ssl_, peer_addr_);
    }
    (void)SSL_do_handshake(ssl_);
    /// Drive the QUIC state machine to flush the Initial CRYPTO frame.
    (void)SSL_handle_events(ssl_);
    drain_to_carrier_unlocked();
    schedule_next_tick_unlocked();
}

void QuicLink::ComposerSession::feed_inbound(
    std::span<const std::uint8_t> bytes,
    std::string                    peer_uri) {
    std::vector<std::vector<std::uint8_t>> plaintext_out;
    bool        fire_handshake_complete = false;
    std::string saved_peer_uri;
    {
        std::lock_guard lk(mu_);
        if (peer_uri_.empty() && !peer_uri.empty()) peer_uri_ = peer_uri;
        if (!bytes.empty() && network_bio_) {
            /// Inject one datagram via `BIO_sendmmsg` so the per-record
            /// (peer, local) tuple survives — plain BIO_write defaults
            /// the peer to 127.0.0.1:1, which breaks QUIC's listener
            /// routing because the (local, peer) tuple inside the
            /// listener no longer matches the ClientHello's connection
            /// id. Our loopback setup pins peer = remote-half's
            /// local_addr; both BIO_ADDR pointers were materialised in
            /// the ctor so the pre-condition holds.
            BIO_MSG msg{};
            msg.data     = const_cast<std::uint8_t*>(bytes.data());
            msg.data_len = bytes.size();
            /// `BIO_dgram_pair` swaps the addresses across halves: a
            /// `BIO_sendmmsg` with (peer=A, local=B) on one half lands
            /// on the other as a `BIO_recvmmsg` with (peer=B, local=A).
            /// We want SSL (reading internal_bio_) to see the datagram
            /// as "from remote peer, to us": peer=our_peer,
            /// local=our_local. Therefore we send from network_bio_
            /// with the inverted tuple.
            msg.peer     = local_addr_;
            msg.local    = peer_addr_;
            std::size_t processed = 0;
            (void)BIO_sendmmsg(network_bio_, &msg, sizeof(msg), 1,
                                0, &processed);
        }
        const bool was_done = handshake_done_;
        pump_unlocked(&plaintext_out);
        if (!was_done && handshake_done_) {
            fire_handshake_complete = (mode_ == Mode::Server);
            saved_peer_uri = peer_uri_;
        }
        schedule_next_tick_unlocked();
    }
    if (fire_handshake_complete) {
        if (auto t = transport_.lock()) {
            t->composer_handshake_complete(composer_id_, saved_peer_uri);
        }
    }
    auto t = transport_.lock();
    if (!t) return;
    QuicLink::ComposerDataSub sub{};
    {
        std::lock_guard sub_lk(t->composer_mu_);
        auto it = t->composer_data_subs_.find(composer_id_);
        if (it != t->composer_data_subs_.end()) sub = it->second;
    }
    for (auto& buf : plaintext_out) {
        if (sub.cb) {
            sub.cb(sub.user_data, composer_id_, buf.data(), buf.size());
        }
        t->bytes_in_.fetch_add(buf.size(), std::memory_order_relaxed);
        t->frames_in_.fetch_add(1,         std::memory_order_relaxed);
    }
}

gn_result_t QuicLink::ComposerSession::do_send(
    std::span<const std::uint8_t> plain) {
    std::lock_guard lk(mu_);
    if (!handshake_done_ || !stream_ssl_) {
        pending_writes_.emplace_back(plain.begin(), plain.end());
        return GN_OK;
    }
    const int n = SSL_write(stream_ssl_, plain.data(),
                              static_cast<int>(plain.size()));
    if (n <= 0) {
        const int err = SSL_get_error(stream_ssl_, n);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            closed_ = true;
            return GN_ERR_NULL_ARG;
        }
    }
    if (ssl_) (void)SSL_handle_events(ssl_);
    else if (listener_) (void)SSL_handle_events(listener_);
    drain_to_carrier_unlocked();
    return GN_OK;
}

void QuicLink::ComposerSession::do_close() {
    std::lock_guard lk(mu_);
    if (closed_) return;
    closed_ = true;
    if (stream_ssl_) (void)SSL_shutdown(stream_ssl_);
    if (ssl_)        (void)SSL_shutdown(ssl_);
    if (auto* drive = active_ssl_unlocked()) {
        (void)SSL_handle_events(drive);
    }
    drain_to_carrier_unlocked();
    auto t = transport_.lock();
    if (t && t->carrier_) (void)t->carrier_->disconnect(l1_id_);
}

void QuicLink::ComposerSession::tick() {
    std::vector<std::vector<std::uint8_t>> plaintext_out;
    {
        std::lock_guard lk(mu_);
        if (closed_) return;
        if (auto* drive = active_ssl_unlocked()) {
            (void)SSL_handle_events(drive);
        }
        pump_unlocked(&plaintext_out);
        schedule_next_tick_unlocked();
    }
    auto t = transport_.lock();
    if (!t) return;
    QuicLink::ComposerDataSub sub{};
    {
        std::lock_guard sub_lk(t->composer_mu_);
        auto it = t->composer_data_subs_.find(composer_id_);
        if (it != t->composer_data_subs_.end()) sub = it->second;
    }
    for (auto& buf : plaintext_out) {
        if (sub.cb) {
            sub.cb(sub.user_data, composer_id_, buf.data(), buf.size());
        }
        t->bytes_in_.fetch_add(buf.size(), std::memory_order_relaxed);
        t->frames_in_.fetch_add(1,         std::memory_order_relaxed);
    }
}

void QuicLink::ComposerSession::schedule_next_tick_unlocked() {
    /// Called under `mu_`. OpenSSL tells us when it next wants
    /// `SSL_handle_events` invoked; we arm an asio timer accordingly.
    SSL* drive = active_ssl_unlocked();
    if (!drive) return;
    struct timeval tv = {};
    int is_infinite   = 0;
    if (SSL_get_event_timeout(drive, &tv, &is_infinite) != 1) return;
    if (is_infinite) return;
    auto delay = std::chrono::microseconds(
        static_cast<std::int64_t>(tv.tv_sec) * 1'000'000 + tv.tv_usec);
    /// Floor at 1 ms so even tight retransmit timers don't busy-spin
    /// through the asio executor.
    if (delay < std::chrono::milliseconds{1}) {
        delay = std::chrono::milliseconds{1};
    }
    tick_timer_.expires_after(delay);
    auto self = shared_from_this();
    tick_timer_.async_wait(
        asio::bind_executor(strand_,
            [self](const std::error_code& ec) {
                if (ec) return;
                self->tick();
            }));
}

void QuicLink::ComposerSession::pump_unlocked(
    std::vector<std::vector<std::uint8_t>>* out) {
    /// Server side: keep polling SSL_accept_connection until a per-peer
    /// connection SSL* surfaces. Once we have one, treat it like the
    /// client's ssl_ — drive handshake → open default stream → read
    /// app data.
    if (mode_ == Mode::Server && !ssl_ && listener_) {
        (void)SSL_handle_events(listener_);
        ssl_ = SSL_accept_connection(listener_, 0);
        if (ssl_) {
            SSL_set_blocking_mode(ssl_, 0);
        }
    }
    if (!ssl_) {
        drain_to_carrier_unlocked();
        return;
    }

    if (!handshake_done_) {
        const int r = SSL_do_handshake(ssl_);
        (void)SSL_handle_events(ssl_);
        if (r == 1) {
            handshake_done_ = true;
            if (mode_ == Mode::Client) {
                stream_ssl_ = SSL_new_stream(ssl_, 0);
            } else {
                /// Server may not yet have observed the client's
                /// initial stream; pump_unlocked retries on each tick.
                stream_ssl_ = SSL_accept_stream(ssl_, 0);
            }
            if (stream_ssl_) {
                for (auto& buf : pending_writes_) {
                    (void)SSL_write(stream_ssl_, buf.data(),
                                     static_cast<int>(buf.size()));
                }
                pending_writes_.clear();
            }
            drain_to_carrier_unlocked();
        } else {
            drain_to_carrier_unlocked();
            return;
        }
    }

    /// Server polls until the peer's stream materialises post-handshake.
    /// `do_send` may have parked application writes in `pending_writes_`
    /// before the stream became available; flush them on the same tick
    /// the stream first surfaces so the round-trip doesn't stall.
    if (!stream_ssl_ && mode_ == Mode::Server) {
        stream_ssl_ = SSL_accept_stream(ssl_, 0);
        if (stream_ssl_) {
            for (auto& buf : pending_writes_) {
                (void)SSL_write(stream_ssl_, buf.data(),
                                 static_cast<int>(buf.size()));
            }
            pending_writes_.clear();
        }
    }

    if (stream_ssl_) {
        std::uint8_t buf[16 * 1024];
        while (true) {
            const int n = SSL_read(stream_ssl_, buf, sizeof(buf));
            if (n > 0) {
                if (out) {
                    out->emplace_back(buf,
                        buf + static_cast<std::size_t>(n));
                }
                continue;
            }
            const int err = SSL_get_error(stream_ssl_, n);
            if (err == SSL_ERROR_WANT_READ) break;
            if (err == SSL_ERROR_ZERO_RETURN) {
                closed_ = true;
                break;
            }
            break;
        }
    }
    drain_to_carrier_unlocked();
}

void QuicLink::ComposerSession::drain_to_carrier_unlocked() {
    auto t = transport_.lock();
    if (!t || !t->carrier_ || !network_bio_) return;
    /// `BIO_recvmmsg` mirrors `BIO_sendmmsg` on the feed side: per-
    /// datagram boundary is preserved + the (peer, local) tuple stamped
    /// by QUIC's state machine surfaces in the BIO_MSG, but we discard
    /// it because our carrier is per-session loopback so the receiving
    /// side already knows what addresses to inject (fixed loopback).
    while (true) {
        std::uint8_t out[16 * 1024];
        BIO_MSG msg{};
        msg.data     = out;
        msg.data_len = sizeof(out);
        std::size_t processed = 0;
        const int rc = BIO_recvmmsg(network_bio_, &msg, sizeof(msg), 1,
                                      0, &processed);
        if (rc != 1 || processed == 0) break;
        (void)t->carrier_->send(
            l1_id_,
            std::span<const std::uint8_t>(out, msg.data_len));
    }
}

}  // namespace gn::link::quic
