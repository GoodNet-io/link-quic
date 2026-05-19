// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/quic/quic.hpp
/// @brief  QUIC transport — OpenSSL-3.6-native QUIC layered on
///         LinkCarrier(udp) per `link.en.md` §8 composer pattern.
///
/// QUIC's role in the stack is to provide
/// `Stream | Reliable | Ordered | EncryptedPath` on top of UDP carriers
/// — including the NAT-traversed UDP that ICE gives. That unlocks
/// Noise IK/XX (which requires reliable+ordered) over peer-to-peer
/// paths and makes "ICE with optional TLS" possible.
///
/// Implementation strategy: mirror the TLS plugin's composer-session
/// split. Each connection-level QUIC handshake lives in a
/// `ComposerSession` (declared in `quic_composer_session.hpp`) that
/// wraps an OpenSSL `SSL*` driven by a memory BIO_pair. The carrier
/// owns the wire. Per-stream `SSL*` objects (via `SSL_new_stream` /
/// `SSL_accept_stream`) hang off the connection but expose to the
/// upper composer as application data over the parent conn id —
/// stream multiplexing surface lives behind a future ABI extension,
/// not in v1.

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>

#include <openssl/ssl.h>

#include <sdk/cpp/link_carrier.hpp>
#include <sdk/cpp/uri.hpp>
#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/trust.h>
#include <sdk/types.h>

namespace gn::link::quic {

class QuicLink : public std::enable_shared_from_this<QuicLink> {
public:
    QuicLink();
    ~QuicLink();

    QuicLink(const QuicLink&)            = delete;
    QuicLink& operator=(const QuicLink&) = delete;

    /// L1 kernel-mode entry points. QUIC is composer-first — these
    /// return GN_ERR_NOT_IMPLEMENTED in v1 because the kernel-managed
    /// QUIC scheme would need a UDP socket that the plugin owns. All
    /// production callers should reach QUIC through the composer
    /// surface below.
    [[nodiscard]] gn_result_t listen(std::string_view uri);
    [[nodiscard]] gn_result_t connect(std::string_view uri);

    [[nodiscard]] gn_result_t send(gn_conn_id_t conn,
                                    std::span<const std::uint8_t> bytes);
    [[nodiscard]] gn_result_t send_batch(
        gn_conn_id_t conn,
        std::span<const std::span<const std::uint8_t>> frames);
    [[nodiscard]] gn_result_t disconnect(gn_conn_id_t conn);

    void set_host_api(const host_api_t* api) noexcept;
    void shutdown();

    [[nodiscard]] std::uint16_t listen_port() const noexcept;
    [[nodiscard]] std::size_t   session_count() const noexcept;

    struct Stats {
        std::uint64_t bytes_in           = 0;
        std::uint64_t bytes_out          = 0;
        std::uint64_t frames_in          = 0;
        std::uint64_t frames_out         = 0;
        std::uint64_t active_connections = 0;
    };
    [[nodiscard]] Stats stats() const noexcept;

    [[nodiscard]] static gn_link_caps_t capabilities() noexcept;

    /// Composer L2 surface. QUIC layers over a UDP carrier — direct UDP
    /// (`quic://host:port` → carrier `udp://host:port`) or ICE
    /// NAT-traversed UDP (`quic+ice://peer-pk-hex` → carrier
    /// `ice://peer-pk-hex`).
    [[nodiscard]] gn_result_t composer_listen(std::string_view uri);
    [[nodiscard]] gn_result_t composer_connect(std::string_view uri,
                                                gn_conn_id_t* out_conn);
    [[nodiscard]] gn_result_t composer_subscribe_data(
        gn_conn_id_t conn, ::gn_link_data_cb_t cb, void* user_data);
    [[nodiscard]] gn_result_t composer_unsubscribe_data(gn_conn_id_t conn);
    [[nodiscard]] gn_result_t composer_subscribe_accept(
        ::gn_link_accept_cb_t cb, void* user_data,
        gn_subscription_id_t* out_token);
    [[nodiscard]] gn_result_t composer_unsubscribe_accept(
        gn_subscription_id_t token);
    [[nodiscard]] gn_result_t composer_listen_port(
        std::uint16_t* out_port) const noexcept;

    static constexpr gn_conn_id_t kComposerIdBit =
        gn_conn_id_t{1} << 63;

    /// Test-fixture cert + key override, mirroring TlsLink's surface.
    void set_server_credentials(std::string_view cert_pem,
                                 std::string_view key_pem);

    /// Toggle peer-cert verification (default-secure baseline = on).
    void set_verify_peer(bool on) noexcept;

private:
    friend class ComposerSession;
    class ComposerSession;

    struct ComposerDataSub {
        ::gn_link_data_cb_t cb        = nullptr;
        void*               user_data = nullptr;
    };
    struct ComposerAcceptSub {
        gn_subscription_id_t  token     = GN_INVALID_SUBSCRIPTION_ID;
        ::gn_link_accept_cb_t cb        = nullptr;
        void*                 user_data = nullptr;
    };

    [[nodiscard]] gn_result_t ensure_carrier(std::string_view scheme);
    /// Lazy-init server / client SSL_CTX with OSSL_QUIC_*_method.
    /// Idempotent.
    [[nodiscard]] gn_result_t ensure_quic_contexts();
    [[nodiscard]] bool load_server_credentials();

    void composer_on_l1_data(gn_conn_id_t l1,
                              std::span<const std::uint8_t> bytes);
    void composer_on_l1_accept(gn_conn_id_t l1,
                                std::string_view peer_uri);
    void composer_handshake_complete(gn_conn_id_t composer_id,
                                      std::string_view peer_uri);
    void composer_drop_session(gn_conn_id_t composer_id);

    asio::io_context                                                 ioc_;
    asio::executor_work_guard<asio::io_context::executor_type>       work_;
    /// Single worker thread to drive periodic `SSL_handle_events` ticks
    /// across all sessions. Per-session strands serialise OpenSSL state
    /// per connection because `SSL*` is not thread-safe.
    std::vector<std::thread>                                         workers_;

    /// QUIC SSL contexts. `SSL_CTX_new(OSSL_QUIC_server_method())` /
    /// `SSL_CTX_new(OSSL_QUIC_client_method())`. Constructed lazily so
    /// callers that only use one direction pay for one.
    SSL_CTX*                                                         server_ctx_ = nullptr;
    SSL_CTX*                                                         client_ctx_ = nullptr;

    std::atomic<bool>                                                shutdown_{false};

    std::atomic<std::uint64_t> bytes_in_{0};
    std::atomic<std::uint64_t> bytes_out_{0};
    std::atomic<std::uint64_t> frames_in_{0};
    std::atomic<std::uint64_t> frames_out_{0};

    std::string                                                      override_cert_pem_;
    std::vector<std::uint8_t>                                        override_key_pem_;
    bool                                                             verify_peer_ = true;

    const host_api_t* api_ = nullptr;
    /// Per-session pending-write hard cap mirrored from operator
    /// config (`limits.pending_queue_bytes_hard`). `do_send` rejects
    /// with `GN_ERR_LIMIT_REACHED` when the active stream's
    /// `pending_bytes_ + new > cap`. Zero (default) preserves the
    /// historical unbounded behaviour.
    std::uint64_t                                                    pending_queue_bytes_hard_ = 0;
    /// Soft watermarks for `notify_backpressure` SOFT / CLEAR
    /// events. Mirrors the TCP path
    /// (`plugins/links/tcp/tcp.cpp:236-270`). When a
    /// ComposerSession's `pending_bytes_` crosses `_high_` upward
    /// the kernel sees one `GN_CONN_EVENT_BACKPRESSURE_SOFT`;
    /// once it falls back below `_low_` one
    /// `GN_CONN_EVENT_BACKPRESSURE_CLEAR` mirrors that. Zero
    /// (default) keeps the silent behaviour.
    std::uint64_t                                                    pending_queue_bytes_high_ = 0;
    std::uint64_t                                                    pending_queue_bytes_low_  = 0;

    /// Composer-mode state. `carrier_` is the UDP carrier the plugin
    /// queries through `gn.link.udp` (or `gn.link.ice` for the
    /// NAT-traversed route).
    std::optional<gn::sdk::LinkCarrier>                              carrier_;
    mutable std::mutex                                               composer_mu_;
    std::unordered_map<gn_conn_id_t,
                       std::shared_ptr<ComposerSession>>             composer_sessions_;
    /// L1 (carrier) conn id → composer (L2) conn id.
    std::unordered_map<gn_conn_id_t, gn_conn_id_t>                   l1_to_composer_;
    std::unordered_map<gn_conn_id_t, ComposerDataSub>                composer_data_subs_;
    std::vector<ComposerAcceptSub>                                   composer_accept_subs_;
    std::atomic<std::uint64_t>                                       next_composer_id_{1};
    std::atomic<std::uint64_t>                                       next_accept_token_{1};
    std::string                                                      carrier_scheme_;
};

}  // namespace gn::link::quic
