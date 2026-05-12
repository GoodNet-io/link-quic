// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/quic/quic.cpp
/// @brief  QuicLink implementation — composer-first L1 plugin.

#include "quic.hpp"
#include "quic_composer_session.hpp"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/quic.h>

#include <sdk/convenience.h>

#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <thread>
#include <utility>

namespace gn::link::quic {

namespace {

/// Detect carrier scheme from the post-`quic://` URI suffix.
/// 64 hex characters → `ice` (peer-pubkey shape, NAT-traversed
/// UDP carrier); anything else → `udp` (direct host:port carrier).
/// The suffix is the operator-visible URI minus the `quic://`
/// prefix, e.g. `127.0.0.1:9999` or
/// `0123456789abcdef...` (64 chars).
[[nodiscard]] std::string_view detect_carrier_scheme(
    std::string_view suffix) noexcept {
    if (suffix.size() != 64) return "udp";
    for (const char c : suffix) {
        const bool hex_lower = c >= '0' && c <= '9';
        const bool hex_alpha = (c >= 'a' && c <= 'f')
                             || (c >= 'A' && c <= 'F');
        if (!hex_lower && !hex_alpha) return "udp";
    }
    return "ice";
}

/// Compose the carrier URI for a detected scheme. `udp://<suffix>`
/// preserves operator-supplied `host:port`; `ice://<suffix>` carries
/// the peer pubkey hex unchanged.
[[nodiscard]] std::string rewrite_carrier_uri(
    std::string_view suffix, std::string_view scheme) {
    std::string out;
    out.reserve(scheme.size() + 3 + suffix.size());
    out.append(scheme);
    out.append("://");
    out.append(suffix);
    return out;
}

}  // namespace

QuicLink::QuicLink()
    : ioc_(),
      work_(asio::make_work_guard(ioc_)) {
    /// Worker pool sized symmetrically with the other link plugins.
    /// Per-session strands serialise OpenSSL state per connection
    /// because `SSL*` is not thread-safe.
    const unsigned hc = std::thread::hardware_concurrency();
    const unsigned n  = std::max(1u, hc / 2);
    workers_.reserve(n);
    for (unsigned i = 0; i < n; ++i) {
        workers_.emplace_back([this] { ioc_.run(); });
    }
}

QuicLink::~QuicLink() {
    try { shutdown(); } catch (...) {}
    sodium_memzero(override_key_pem_.data(), override_key_pem_.size());
    if (server_ctx_) { SSL_CTX_free(server_ctx_); server_ctx_ = nullptr; }
    if (client_ctx_) { SSL_CTX_free(client_ctx_); client_ctx_ = nullptr; }
}

void QuicLink::set_host_api(const host_api_t* api) noexcept {
    api_         = api;
    verify_peer_ = true;
}

void QuicLink::set_server_credentials(std::string_view cert_pem,
                                       std::string_view key_pem) {
    override_cert_pem_.assign(cert_pem.begin(), cert_pem.end());
    sodium_memzero(override_key_pem_.data(), override_key_pem_.size());
    override_key_pem_.assign(
        reinterpret_cast<const std::uint8_t*>(key_pem.data()),
        reinterpret_cast<const std::uint8_t*>(
            key_pem.data() + key_pem.size()));
}

void QuicLink::set_verify_peer(bool on) noexcept {
    verify_peer_ = on;
    if (client_ctx_) {
        SSL_CTX_set_verify(client_ctx_,
                            on ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
                            nullptr);
    }
}

gn_link_caps_t QuicLink::capabilities() noexcept {
    gn_link_caps_t c{};
    c.flags = GN_LINK_CAP_STREAM
            | GN_LINK_CAP_RELIABLE
            | GN_LINK_CAP_ORDERED
            | GN_LINK_CAP_ENCRYPTED_PATH;
    /// QUIC datagram payload ceiling: 16 KiB per app frame keeps us
    /// inside a single STREAM frame without dependent flow control
    /// interactions. Operator tuning lands when stream-level caps
    /// arrive through extension.
    c.max_payload = 16 * 1024;
    return c;
}

std::uint16_t QuicLink::listen_port() const noexcept {
    /// QUIC kernel mode is not implemented; composer-mode port lives
    /// on the L1 carrier.
    if (carrier_) return carrier_->listen_port();
    return 0;
}

std::size_t QuicLink::session_count() const noexcept {
    std::lock_guard lk(composer_mu_);
    return composer_sessions_.size();
}

QuicLink::Stats QuicLink::stats() const noexcept {
    Stats s{};
    s.bytes_in            = bytes_in_.load(std::memory_order_relaxed);
    s.bytes_out           = bytes_out_.load(std::memory_order_relaxed);
    s.frames_in           = frames_in_.load(std::memory_order_relaxed);
    s.frames_out          = frames_out_.load(std::memory_order_relaxed);
    s.active_connections  = session_count();
    return s;
}

gn_result_t QuicLink::listen(std::string_view) {
    /// QUIC kernel mode deliberately unsupported in v1 — production
    /// callers reach through composer surface.
    return GN_ERR_NOT_IMPLEMENTED;
}

gn_result_t QuicLink::connect(std::string_view) {
    return GN_ERR_NOT_IMPLEMENTED;
}

gn_result_t QuicLink::send(gn_conn_id_t conn,
                            std::span<const std::uint8_t> bytes) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_INVALID_STATE;
    if (!(conn & kComposerIdBit)) return GN_ERR_NOT_FOUND;
    std::shared_ptr<ComposerSession> cs;
    {
        std::lock_guard lk(composer_mu_);
        auto it = composer_sessions_.find(conn);
        if (it == composer_sessions_.end()) return GN_ERR_NOT_FOUND;
        cs = it->second;
    }
    bytes_out_.fetch_add(bytes.size(), std::memory_order_relaxed);
    frames_out_.fetch_add(1,           std::memory_order_relaxed);
    return cs->do_send(bytes);
}

gn_result_t QuicLink::send_batch(
    gn_conn_id_t conn,
    std::span<const std::span<const std::uint8_t>> frames) {
    for (const auto& f : frames) {
        if (const auto rc = send(conn, f); rc != GN_OK) return rc;
    }
    return GN_OK;
}

gn_result_t QuicLink::disconnect(gn_conn_id_t conn) {
    if (!(conn & kComposerIdBit)) return GN_OK;
    std::shared_ptr<ComposerSession> cs;
    {
        std::lock_guard lk(composer_mu_);
        auto it = composer_sessions_.find(conn);
        if (it == composer_sessions_.end()) return GN_OK;
        cs = it->second;
        composer_data_subs_.erase(conn);
    }
    cs->do_close();
    composer_drop_session(conn);
    return GN_OK;
}

void QuicLink::shutdown() {
    if (shutdown_.exchange(true, std::memory_order_acq_rel)) return;

    std::vector<std::shared_ptr<ComposerSession>> composer_drain;
    {
        std::lock_guard lk(composer_mu_);
        composer_drain.reserve(composer_sessions_.size());
        for (auto& [_, cs] : composer_sessions_) {
            composer_drain.push_back(cs);
        }
        composer_sessions_.clear();
        l1_to_composer_.clear();
        composer_data_subs_.clear();
        composer_accept_subs_.clear();
    }
    for (auto& cs : composer_drain) cs->do_close();
    carrier_.reset();

    work_.reset();
    ioc_.stop();
    for (auto& w : workers_) {
        if (w.joinable()) w.join();
    }
    workers_.clear();
}

gn_result_t QuicLink::ensure_carrier(std::string_view scheme) {
    if (carrier_) {
        if (!carrier_scheme_.empty() && carrier_scheme_ != scheme) {
            return GN_ERR_INVALID_STATE;
        }
        return GN_OK;
    }
    if (!api_) return GN_ERR_INVALID_STATE;
    auto opt = gn::sdk::LinkCarrier::query(api_, scheme);
    if (!opt) return GN_ERR_NOT_FOUND;
    carrier_.emplace(std::move(*opt));
    carrier_scheme_ = std::string(scheme);
    return GN_OK;
}

namespace {

/// ALPN select callback for the server context. QUIC mandates ALPN;
/// without this callback the server rejects every handshake with
/// `no_application_protocol`. The plugin advertises a single token,
/// "gn-v1", matching the client-side `SSL_set_alpn_protos` in
/// `ComposerSession`. Operator-controlled ALPN list is a future
/// `gn.link.quic.alpn` config slot.
int alpn_select_gn_v1(SSL*, const unsigned char** out,
                      unsigned char* outlen,
                      const unsigned char* in, unsigned int inlen,
                      void*) {
    static const unsigned char kServer[] = {'g', 'n', '-', 'v', '1'};
    const std::uint8_t target_len = static_cast<std::uint8_t>(sizeof(kServer));
    for (unsigned int i = 0; i + 1 + target_len <= inlen; ) {
        const std::uint8_t l = in[i];
        if (l == target_len &&
            std::memcmp(in + i + 1, kServer, target_len) == 0) {
            *out    = in + i + 1;
            *outlen = target_len;
            return SSL_TLSEXT_ERR_OK;
        }
        i += 1 + l;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

}  // namespace

gn_result_t QuicLink::ensure_quic_contexts() {
    if (!server_ctx_) {
        server_ctx_ = SSL_CTX_new(OSSL_QUIC_server_method());
        if (!server_ctx_) return GN_ERR_NULL_ARG;
        SSL_CTX_set_alpn_select_cb(server_ctx_, &alpn_select_gn_v1, nullptr);
    }
    if (!client_ctx_) {
        client_ctx_ = SSL_CTX_new(OSSL_QUIC_client_method());
        if (!client_ctx_) return GN_ERR_NULL_ARG;
        SSL_CTX_set_verify(client_ctx_,
                            verify_peer_ ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
                            nullptr);
        SSL_CTX_set_default_verify_paths(client_ctx_);
    }
    return GN_OK;
}

bool QuicLink::load_server_credentials() {
    if (!server_ctx_) return false;
    if (!override_cert_pem_.empty() && !override_key_pem_.empty()) {
        BIO* cert_bio = BIO_new_mem_buf(
            override_cert_pem_.data(),
            static_cast<int>(override_cert_pem_.size()));
        BIO* key_bio = BIO_new_mem_buf(
            override_key_pem_.data(),
            static_cast<int>(override_key_pem_.size()));
        X509* cert       = cert_bio ? PEM_read_bio_X509(cert_bio, nullptr,
                                                          nullptr, nullptr) : nullptr;
        EVP_PKEY* key    = key_bio  ? PEM_read_bio_PrivateKey(key_bio, nullptr,
                                                                nullptr, nullptr) : nullptr;
        bool ok = false;
        if (cert && key) {
            ok = SSL_CTX_use_certificate(server_ctx_, cert) == 1
              && SSL_CTX_use_PrivateKey(server_ctx_, key) == 1;
        }
        /// PEM refcount discipline (Track C.4): `SSL_CTX_use_certificate`
        /// bumps cert's refcount; we MUST `X509_free` here to release
        /// our local reference, else cert + linked ASN1_STRING strings
        /// leak. Same shape for EVP_PKEY. Without these frees ASan
        /// reports indirect leaks chained from `PEM_ASN1_read_bio`.
        if (cert) X509_free(cert);
        if (key)  EVP_PKEY_free(key);
        if (cert_bio) BIO_free(cert_bio);
        if (key_bio)  BIO_free(key_bio);
        if (ok) {
            sodium_memzero(override_key_pem_.data(),
                            override_key_pem_.size());
            override_key_pem_.clear();
        }
        return ok;
    }
    return false;
}

gn_result_t QuicLink::composer_listen(std::string_view uri) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_INVALID_STATE;
    if (!uri.starts_with("quic://")) {
        gn_log_warn(api_, "quic: composer_listen reject malformed uri "
                          "(expected quic://, got %.*s)",
                    static_cast<int>(uri.size()), uri.data());
        return GN_ERR_INVALID_ENVELOPE;
    }

    const auto suffix = uri.substr(7);
    const auto carrier_scheme = detect_carrier_scheme(suffix);
    if (const auto rc = ensure_carrier(carrier_scheme); rc != GN_OK) {
        gn_log_warn(api_, "quic: composer_listen ensure_carrier(%.*s) "
                          "failed rc=%d",
                    static_cast<int>(carrier_scheme.size()),
                    carrier_scheme.data(), rc);
        return rc;
    }
    if (const auto rc = ensure_quic_contexts(); rc != GN_OK) {
        gn_log_warn(api_, "quic: composer_listen ensure_quic_contexts "
                          "failed rc=%d", rc);
        return rc;
    }
    if (!load_server_credentials()) {
        gn_log_warn(api_, "quic: composer_listen no server credentials "
                          "(set_server_credentials() not called?)");
        return GN_ERR_NULL_ARG;
    }

    const std::string l1_uri = rewrite_carrier_uri(suffix, carrier_scheme);

    auto self_weak = weak_from_this();
    const auto rc = carrier_->on_accept(
        [self_weak](gn_conn_id_t l1, std::string_view peer_uri) {
            if (auto t = self_weak.lock()) {
                t->composer_on_l1_accept(l1, peer_uri);
            }
        });
    if (rc != GN_OK) {
        gn_log_warn(api_, "quic: composer_listen on_accept rc=%d", rc);
        return rc;
    }
    const auto listen_rc = carrier_->listen(l1_uri);
    if (listen_rc != GN_OK) {
        gn_log_warn(api_, "quic: composer_listen carrier listen %s "
                          "failed rc=%d", l1_uri.c_str(), listen_rc);
    } else {
        gn_log_info(api_, "quic: composer_listen bound %s", l1_uri.c_str());
    }
    return listen_rc;
}

gn_result_t QuicLink::composer_connect(std::string_view uri,
                                        gn_conn_id_t* out_conn) {
    if (!out_conn) return GN_ERR_NULL_ARG;
    *out_conn = GN_INVALID_ID;
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_INVALID_STATE;
    if (!uri.starts_with("quic://")) {
        gn_log_warn(api_, "quic: composer_connect reject malformed uri "
                          "(expected quic://, got %.*s)",
                    static_cast<int>(uri.size()), uri.data());
        return GN_ERR_INVALID_ENVELOPE;
    }

    const auto suffix = uri.substr(7);
    const auto carrier_scheme = detect_carrier_scheme(suffix);
    if (const auto rc = ensure_carrier(carrier_scheme); rc != GN_OK) {
        gn_log_warn(api_, "quic: composer_connect ensure_carrier(%.*s) "
                          "rc=%d",
                    static_cast<int>(carrier_scheme.size()),
                    carrier_scheme.data(), rc);
        return rc;
    }
    if (const auto rc = ensure_quic_contexts(); rc != GN_OK) {
        gn_log_warn(api_, "quic: composer_connect ensure_quic_contexts "
                          "rc=%d", rc);
        return rc;
    }

    const std::string l1_uri = rewrite_carrier_uri(suffix, carrier_scheme);

    gn_conn_id_t l1 = GN_INVALID_ID;
    if (const auto rc = carrier_->connect(l1_uri, &l1); rc != GN_OK) {
        gn_log_warn(api_, "quic: composer_connect carrier connect %s "
                          "rc=%d", l1_uri.c_str(), rc);
        return rc;
    }

    const gn_conn_id_t composer_id =
        next_composer_id_.fetch_add(1, std::memory_order_relaxed)
        | kComposerIdBit;
    auto cs = std::make_shared<ComposerSession>(
        client_ctx_, ComposerSession::Mode::Client,
        l1, composer_id, weak_from_this(), ioc_);
    {
        std::lock_guard lk(composer_mu_);
        composer_sessions_[composer_id] = cs;
        l1_to_composer_[l1] = composer_id;
    }
    auto self_weak = weak_from_this();
    (void)carrier_->on_data(
        l1,
        [self_weak](gn_conn_id_t lid,
                    std::span<const std::uint8_t> bytes) {
            if (auto t = self_weak.lock()) {
                t->composer_on_l1_data(lid, bytes);
            }
        });
    cs->kick_client_handshake(std::string(uri));
    *out_conn = composer_id;
    return GN_OK;
}

gn_result_t QuicLink::composer_subscribe_data(gn_conn_id_t conn,
                                                ::gn_link_data_cb_t cb,
                                                void* user_data) {
    if (!cb) return GN_ERR_NULL_ARG;
    if (!(conn & kComposerIdBit)) return GN_ERR_NOT_FOUND;
    std::lock_guard lk(composer_mu_);
    if (composer_sessions_.find(conn) == composer_sessions_.end()) {
        return GN_ERR_NOT_FOUND;
    }
    composer_data_subs_[conn] = ComposerDataSub{cb, user_data};
    return GN_OK;
}

gn_result_t QuicLink::composer_unsubscribe_data(gn_conn_id_t conn) {
    if (!(conn & kComposerIdBit)) return GN_OK;
    std::lock_guard lk(composer_mu_);
    composer_data_subs_.erase(conn);
    return GN_OK;
}

gn_result_t QuicLink::composer_subscribe_accept(
    ::gn_link_accept_cb_t cb,
    void* user_data,
    gn_subscription_id_t* out_token) {
    if (!cb || !out_token) return GN_ERR_NULL_ARG;
    const gn_subscription_id_t token =
        next_accept_token_.fetch_add(1, std::memory_order_relaxed);
    std::lock_guard lk(composer_mu_);
    composer_accept_subs_.push_back(
        ComposerAcceptSub{token, cb, user_data});
    *out_token = token;
    return GN_OK;
}

gn_result_t QuicLink::composer_unsubscribe_accept(
    gn_subscription_id_t token) {
    std::lock_guard lk(composer_mu_);
    auto it = std::remove_if(
        composer_accept_subs_.begin(), composer_accept_subs_.end(),
        [token](const ComposerAcceptSub& s) { return s.token == token; });
    composer_accept_subs_.erase(it, composer_accept_subs_.end());
    return GN_OK;
}

gn_result_t QuicLink::composer_listen_port(
    std::uint16_t* out_port) const noexcept {
    if (!out_port) return GN_ERR_NULL_ARG;
    *out_port = 0;
    if (!carrier_) return GN_ERR_INVALID_STATE;
    const auto port = carrier_->listen_port();
    if (port == 0) return GN_ERR_INVALID_STATE;
    *out_port = port;
    return GN_OK;
}

void QuicLink::composer_on_l1_accept(gn_conn_id_t l1,
                                       std::string_view peer_uri) {
    const gn_conn_id_t composer_id =
        next_composer_id_.fetch_add(1, std::memory_order_relaxed)
        | kComposerIdBit;
    auto cs = std::make_shared<ComposerSession>(
        server_ctx_, ComposerSession::Mode::Server,
        l1, composer_id, weak_from_this(), ioc_);
    {
        std::lock_guard lk(composer_mu_);
        composer_sessions_[composer_id] = cs;
        l1_to_composer_[l1] = composer_id;
    }
    auto self_weak = weak_from_this();
    if (carrier_) {
        (void)carrier_->on_data(
            l1,
            [self_weak](gn_conn_id_t lid,
                        std::span<const std::uint8_t> bytes) {
                if (auto t = self_weak.lock()) {
                    t->composer_on_l1_data(lid, bytes);
                }
            });
    }
    cs->feed_inbound({}, std::string(peer_uri));
}

void QuicLink::composer_on_l1_data(gn_conn_id_t l1,
                                     std::span<const std::uint8_t> bytes) {
    std::shared_ptr<ComposerSession> cs;
    {
        std::lock_guard lk(composer_mu_);
        auto it = l1_to_composer_.find(l1);
        if (it == l1_to_composer_.end()) return;
        auto sit = composer_sessions_.find(it->second);
        if (sit == composer_sessions_.end()) return;
        cs = sit->second;
    }
    cs->feed_inbound(bytes, {});
}

void QuicLink::composer_handshake_complete(gn_conn_id_t composer_id,
                                             std::string_view peer_uri) {
    std::vector<ComposerAcceptSub> snapshot;
    {
        std::lock_guard lk(composer_mu_);
        snapshot = composer_accept_subs_;
    }
    const std::string peer(peer_uri);
    for (const auto& s : snapshot) {
        if (s.cb) s.cb(s.user_data, composer_id, peer.c_str());
    }
}

void QuicLink::composer_drop_session(gn_conn_id_t composer_id) {
    std::shared_ptr<ComposerSession> cs;
    {
        std::lock_guard lk(composer_mu_);
        auto it = composer_sessions_.find(composer_id);
        if (it == composer_sessions_.end()) return;
        cs = std::move(it->second);
        l1_to_composer_.erase(cs->l1_id());
        composer_sessions_.erase(it);
        composer_data_subs_.erase(composer_id);
    }
}

}  // namespace gn::link::quic
