// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/quic/quic_composer_session.hpp
/// @brief  QuicLink::ComposerSession — OpenSSL-3.6-native QUIC per
///         the listener-pattern required by `OSSL_QUIC_*_method`.
///
/// Architecture differs from TLS/DTLS ComposerSession in two important
/// ways forced by OpenSSL's QUIC API:
///   1. Datagram-boundary BIO pair (`BIO_new_bio_dgram_pair`) instead
///      of streaming pair — QUIC requires one-record-per-BIO_read.
///   2. Server side is **listener-pattern**: per-peer
///      `SSL_new_listener(server_ctx)` extracts a per-connection `SSL*`
///      through `SSL_accept_connection`. Client side keeps the direct
///      `SSL_new` shape.
///
/// Per-peer listener wastes ~50 KB / server peer (one listener struct
/// per peer); accepted in v1 as the cleanest mapping to the composer
/// pattern (one L1 carrier conn = one peer = one ComposerSession). A
/// shared listener with carrier-side address demux is the v1.1 path.

#pragma once

#include "quic.hpp"

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <asio/steady_timer.hpp>
#include <asio/strand.hpp>

#include <cstdint>
#include <deque>
#include <mutex>
#include <span>
#include <string>
#include <vector>

namespace gn::link::quic {

class QuicLink::ComposerSession
    : public std::enable_shared_from_this<QuicLink::ComposerSession> {
public:
    enum class Mode { Server, Client };

    ComposerSession(SSL_CTX*               ctx,
                     Mode                   mode,
                     gn_conn_id_t           l1_id,
                     gn_conn_id_t           composer_id,
                     std::weak_ptr<QuicLink> transport,
                     asio::io_context&      ioc);

    ComposerSession(const ComposerSession&)            = delete;
    ComposerSession& operator=(const ComposerSession&) = delete;

    ~ComposerSession();

    [[nodiscard]] gn_conn_id_t l1_id() const noexcept       { return l1_id_; }
    [[nodiscard]] gn_conn_id_t composer_id() const noexcept { return composer_id_; }

    /// Client-side kickoff. Sets ALPN, initial peer address, then
    /// drives the initial CRYPTO frame out through the carrier.
    void kick_client_handshake(std::string peer_uri);

    /// Inbound encrypted datagram from the carrier. Boundary preserved
    /// by `BIO_new_bio_dgram_pair` — one BIO_write per datagram.
    void feed_inbound(std::span<const std::uint8_t> bytes,
                       std::string peer_uri);

    /// Application-level send. Queues until handshake done and stream
    /// is open, then writes through the connection-default stream.
    gn_result_t do_send(std::span<const std::uint8_t> plain);

    void do_close();

private:
    /// Tick: SSL_handle_events on whichever `SSL*` is active (listener
    /// pre-accept, connection post-accept) → drain to carrier →
    /// reschedule based on SSL_get_event_timeout.
    void tick();
    void schedule_next_tick_unlocked();
    /// Drive the QUIC state machine: SSL_handle_events on the active
    /// SSL*, server-side polls SSL_accept_connection until it yields,
    /// then drives handshake on the per-peer connection SSL*, then
    /// opens/accepts the default bidirectional stream.
    void pump_unlocked(std::vector<std::vector<std::uint8_t>>* out);
    void drain_to_carrier_unlocked();

    /// Pick the SSL* whose `SSL_handle_events` should fire — listener
    /// pre-accept, connection post-accept. Returns nullptr if neither
    /// is set yet (shouldn't happen post-ctor).
    [[nodiscard]] SSL* active_ssl_unlocked() const noexcept;

    Mode                                   mode_;
    gn_conn_id_t                           l1_id_;
    gn_conn_id_t                           composer_id_;
    std::weak_ptr<QuicLink>                transport_;

    std::mutex                             mu_;
    /// Server-side listener (`SSL_new_listener`). Null on client side.
    /// Allocated in ctor, kept alive for the lifetime of the session
    /// because the connection SSL* below is owned by the listener.
    SSL*                                   listener_       = nullptr;
    /// Connection-level SSL*. Server side: acquired post-handshake
    /// through `SSL_accept_connection(listener_)`. Client side:
    /// allocated in ctor through `SSL_new(client_ctx)`.
    SSL*                                   ssl_            = nullptr;
    /// Memory BIO pair — datagram-preserving. We own the
    /// `network_bio_` half explicitly; `internal_bio_` is consumed by
    /// the SSL/listener once `SSL_set_bio` is called.
    BIO*                                   internal_bio_   = nullptr;
    BIO*                                   network_bio_    = nullptr;
    /// Synthetic BIO addresses. QUIC's memory BIO needs *some* address
    /// stamped on every datagram out, even if it's loopback. The
    /// initial-peer-addr on the client side and the local-addr on
    /// both halves of the pair use these.
    BIO_ADDR*                              local_addr_     = nullptr;
    BIO_ADDR*                              peer_addr_      = nullptr;
    /// Connection-default bidirectional stream `SSL*`. Allocated
    /// post-handshake via `SSL_new_stream` (client side) or
    /// `SSL_accept_stream` (server side polled in `pump_unlocked`).
    SSL*                                   stream_ssl_     = nullptr;
    bool                                   handshake_done_ = false;
    bool                                   closed_         = false;
    std::string                            peer_uri_;
    std::deque<std::vector<std::uint8_t>>  pending_writes_;
    /// Sum of bytes currently parked in `pending_writes_`. Bounded
    /// by `QuicLink::pending_queue_bytes_hard_` (operator config
    /// `limits.pending_queue_bytes_hard`); zero means unbounded.
    /// Mirrors the same invariant TCP / IPC / TLS / WS plugins
    /// uphold so an out-of-control producer can't drive the
    /// stream's memory footprint without limit.
    std::size_t                            pending_bytes_  = 0;
    /// One-shot rising-edge state for `GN_CONN_EVENT_BACKPRESSURE_SOFT`.
    /// `pending_bytes_` is mutated under `mu_`, so a plain `bool`
    /// is enough — no atomic. Cleared when `pending_bytes_` falls
    /// back below the low watermark and `CLEAR` is emitted.
    bool                                   soft_signaled_  = false;

    asio::strand<asio::io_context::executor_type> strand_;
    asio::steady_timer                            tick_timer_;
};

}  // namespace gn::link::quic
