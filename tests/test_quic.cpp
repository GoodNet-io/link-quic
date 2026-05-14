// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/quic/tests/test_quic.cpp
/// @brief  QUIC plugin — smoke + end-to-end handshake / payload
///         roundtrip over a UdpLink composer carrier. Layout follows
///         `plugins/links/tls/tests/test_dtls.cpp`.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <quic.hpp>
#include <udp.hpp>
#include <link_ice.hpp>

#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

#include "../../tls/tests/support/test_self_signed_cert.hpp"

namespace {

using gn::link::quic::QuicLink;

struct UdpCarrierBridge {
    std::shared_ptr<gn::link::udp::UdpLink> udp;
    gn_link_api_t vtable{};

    UdpCarrierBridge() : udp(std::make_shared<gn::link::udp::UdpLink>()) {
        vtable.api_size             = sizeof(vtable);
        vtable.get_stats            = &s_get_stats;
        vtable.get_capabilities     = &s_get_caps;
        vtable.send                 = &s_send;
        vtable.send_batch           = &s_send_batch;
        vtable.close                = &s_close;
        vtable.listen               = &s_listen;
        vtable.connect              = &s_connect;
        vtable.subscribe_data       = &s_subscribe_data;
        vtable.unsubscribe_data     = &s_unsubscribe_data;
        vtable.subscribe_accept     = &s_subscribe_accept;
        vtable.unsubscribe_accept   = &s_unsubscribe_accept;
        vtable.composer_listen_port = &s_listen_port;
        vtable.ctx                  = this;
    }

    static gn_result_t s_get_stats(void*, gn_link_stats_t* out) {
        if (out) std::memset(out, 0, sizeof(*out));
        return GN_OK;
    }
    static gn_result_t s_get_caps(void*, gn_link_caps_t* out) {
        if (out) *out = gn::link::udp::UdpLink::capabilities();
        return GN_OK;
    }
    static gn_result_t s_send(void* ctx, gn_conn_id_t c,
                               const std::uint8_t* b, std::size_t n) {
        return static_cast<UdpCarrierBridge*>(ctx)->udp->send(
            c, std::span<const std::uint8_t>(b, n));
    }
    static gn_result_t s_send_batch(void* ctx, gn_conn_id_t c,
                                     const gn_byte_span_t* batch,
                                     std::size_t count) {
        std::vector<std::span<const std::uint8_t>> frames;
        frames.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            frames.emplace_back(batch[i].bytes, batch[i].size);
        }
        return static_cast<UdpCarrierBridge*>(ctx)->udp->send_batch(c,
            std::span<const std::span<const std::uint8_t>>(frames));
    }
    static gn_result_t s_close(void* ctx, gn_conn_id_t c, int) {
        return static_cast<UdpCarrierBridge*>(ctx)->udp->disconnect(c);
    }
    static gn_result_t s_listen(void* ctx, const char* uri) {
        return static_cast<UdpCarrierBridge*>(ctx)
            ->udp->composer_listen(uri);
    }
    static gn_result_t s_connect(void* ctx, const char* uri,
                                  gn_conn_id_t* out) {
        return static_cast<UdpCarrierBridge*>(ctx)
            ->udp->composer_connect(uri, out);
    }
    static gn_result_t s_subscribe_data(void* ctx, gn_conn_id_t c,
                                          gn_link_data_cb_t cb, void* ud) {
        return static_cast<UdpCarrierBridge*>(ctx)
            ->udp->composer_subscribe_data(c, cb, ud);
    }
    static gn_result_t s_unsubscribe_data(void* ctx, gn_conn_id_t c) {
        return static_cast<UdpCarrierBridge*>(ctx)
            ->udp->composer_unsubscribe_data(c);
    }
    static gn_result_t s_subscribe_accept(void* ctx,
                                            gn_link_accept_cb_t cb,
                                            void* ud,
                                            gn_subscription_id_t* out) {
        return static_cast<UdpCarrierBridge*>(ctx)
            ->udp->composer_subscribe_accept(cb, ud, out);
    }
    static gn_result_t s_unsubscribe_accept(void* ctx,
                                              gn_subscription_id_t tok) {
        return static_cast<UdpCarrierBridge*>(ctx)
            ->udp->composer_unsubscribe_accept(tok);
    }
    static gn_result_t s_listen_port(void* ctx, std::uint16_t* out) {
        return static_cast<UdpCarrierBridge*>(ctx)
            ->udp->composer_listen_port(out);
    }
};

/// Bridge wrapping a real `IceLink` behind a `gn_link_api_t` vtable
/// that `LinkCarrier::query` can resolve through the harness's
/// `query_extension_checked`. Mirrors `UdpCarrierBridge` and surfaces
/// the full ICE composer slot family (listen / connect /
/// subscribe_data / subscribe_accept).
struct IceCarrierBridge {
    std::shared_ptr<gn::link::ice::IceLink> ice;
    gn_link_api_t vtable{};

    IceCarrierBridge()
        : ice(std::make_shared<gn::link::ice::IceLink>()) {
        vtable.api_size             = sizeof(vtable);
        vtable.get_stats            = &s_get_stats;
        vtable.get_capabilities     = &s_get_caps;
        vtable.send                 = &s_send;
        vtable.send_batch           = &s_send_batch;
        vtable.close                = &s_close;
        vtable.listen               = &s_listen;
        vtable.connect              = &s_connect;
        vtable.subscribe_data       = &s_subscribe_data;
        vtable.unsubscribe_data     = &s_unsubscribe_data;
        vtable.subscribe_accept     = &s_subscribe_accept;
        vtable.unsubscribe_accept   = &s_unsubscribe_accept;
        vtable.composer_listen_port = &s_listen_port;
        vtable.ctx                  = this;
    }

    static gn_result_t s_get_stats(void*, gn_link_stats_t* out) {
        if (out) std::memset(out, 0, sizeof(*out));
        return GN_OK;
    }
    static gn_result_t s_get_caps(void*, gn_link_caps_t* out) {
        if (out) *out = gn::link::ice::IceLink::capabilities();
        return GN_OK;
    }
    static gn_result_t s_send(void* ctx, gn_conn_id_t c,
                               const std::uint8_t* b, std::size_t n) {
        return static_cast<IceCarrierBridge*>(ctx)->ice->send(
            c, std::span<const std::uint8_t>(b, n));
    }
    static gn_result_t s_send_batch(void*, gn_conn_id_t,
                                     const gn_byte_span_t*, std::size_t) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    static gn_result_t s_close(void* ctx, gn_conn_id_t c, int) {
        return static_cast<IceCarrierBridge*>(ctx)->ice->disconnect(c);
    }
    static gn_result_t s_listen(void* ctx, const char* uri) {
        return static_cast<IceCarrierBridge*>(ctx)
            ->ice->composer_listen(uri);
    }
    static gn_result_t s_connect(void* ctx, const char* uri,
                                  gn_conn_id_t* out) {
        return static_cast<IceCarrierBridge*>(ctx)
            ->ice->composer_connect(uri, out);
    }
    static gn_result_t s_subscribe_data(void* ctx, gn_conn_id_t c,
                                          gn_link_data_cb_t cb, void* ud) {
        return static_cast<IceCarrierBridge*>(ctx)
            ->ice->composer_subscribe_data(c, cb, ud);
    }
    static gn_result_t s_unsubscribe_data(void* ctx, gn_conn_id_t c) {
        return static_cast<IceCarrierBridge*>(ctx)
            ->ice->composer_unsubscribe_data(c);
    }
    static gn_result_t s_subscribe_accept(void* ctx,
                                            gn_link_accept_cb_t cb,
                                            void* ud,
                                            gn_subscription_id_t* out) {
        return static_cast<IceCarrierBridge*>(ctx)
            ->ice->composer_subscribe_accept(cb, ud, out);
    }
    static gn_result_t s_unsubscribe_accept(void* ctx,
                                              gn_subscription_id_t tok) {
        return static_cast<IceCarrierBridge*>(ctx)
            ->ice->composer_unsubscribe_accept(tok);
    }
    static gn_result_t s_listen_port(void* ctx, std::uint16_t* out) {
        return static_cast<IceCarrierBridge*>(ctx)
            ->ice->composer_listen_port(out);
    }
};

struct QuicHarness {
    std::mutex                              mu;
    std::atomic<gn_conn_id_t>               next_id{1};

    UdpCarrierBridge udp_bridge;

    static gn_result_t s_notify_connect(void* host_ctx,
                                         const std::uint8_t*,
                                         const char*,
                                         gn_trust_class_t,
                                         gn_handshake_role_t,
                                         gn_conn_id_t* out_conn) {
        auto* h = static_cast<QuicHarness*>(host_ctx);
        *out_conn = h->next_id.fetch_add(1);
        return GN_OK;
    }
    static gn_result_t s_notify_inbound(void*, gn_conn_id_t,
                                         const std::uint8_t*,
                                         std::size_t) {
        return GN_OK;
    }
    static gn_result_t s_notify_disconnect(void*, gn_conn_id_t,
                                            gn_result_t) {
        return GN_OK;
    }
    static gn_result_t s_kick(void*, gn_conn_id_t) { return GN_OK; }
    /// Optional ICE carrier bridge — only constructed when the test
    /// uses `quic://<64-hex>` URIs that the carrier-scheme detection
    /// in `QuicLink` routes through `gn.link.ice`. Lazy so the
    /// existing UDP-only tests stay unchanged.
    std::optional<IceCarrierBridge> ice_bridge;
    /// Caller passes the same `host_api_t` pointer they use for the
    /// QuicLink + UdpLink so all three plugins share lifetime —
    /// embedding a local copy here would dangle as soon as
    /// `enable_ice` returned.
    void enable_ice(const host_api_t* api) {
        if (!ice_bridge) {
            ice_bridge.emplace();
            ice_bridge->ice->set_host_api(api);
        }
    }

    static gn_result_t s_query_extension(void* host_ctx, const char* name,
                                           std::uint32_t version,
                                           const void** out) {
        if (!out) return GN_ERR_NULL_ARG;
        *out = nullptr;
        if (version != GN_EXT_LINK_VERSION) return GN_ERR_NOT_FOUND;
        auto* h = static_cast<QuicHarness*>(host_ctx);
        const std::string_view ext{name};
        if (ext == "gn.link.udp") {
            *out = &h->udp_bridge.vtable;
            return GN_OK;
        }
        if (ext == "gn.link.ice" && h->ice_bridge) {
            *out = &h->ice_bridge->vtable;
            return GN_OK;
        }
        return GN_ERR_NOT_FOUND;
    }

    host_api_t make_api() {
        host_api_t api{};
        api.api_size                 = sizeof(host_api_t);
        api.host_ctx                 = this;
        api.notify_connect           = &s_notify_connect;
        api.notify_inbound_bytes     = &s_notify_inbound;
        api.notify_disconnect        = &s_notify_disconnect;
        api.kick_handshake           = &s_kick;
        api.query_extension_checked  = &s_query_extension;
        return api;
    }
};

struct DataRecorder {
    mutable std::mutex                     mu;
    std::vector<std::vector<std::uint8_t>> frames;
    std::atomic<std::size_t>               count{0};
    static void thunk(void* user_data, gn_conn_id_t,
                      const std::uint8_t* bytes, std::size_t size) {
        auto* self = static_cast<DataRecorder*>(user_data);
        {
            std::lock_guard lk(self->mu);
            self->frames.emplace_back(bytes, bytes + size);
        }
        self->count.fetch_add(1, std::memory_order_relaxed);
    }
};

struct AcceptRecorder {
    std::atomic<gn_conn_id_t> last{GN_INVALID_ID};
    std::atomic<std::size_t>  count{0};
    static void thunk(void* user_data, gn_conn_id_t conn, const char*) {
        auto* self = static_cast<AcceptRecorder*>(user_data);
        self->last.store(conn, std::memory_order_release);
        self->count.fetch_add(1, std::memory_order_relaxed);
    }
};

bool wait_for(auto&& predicate,
              std::chrono::milliseconds timeout =
                  std::chrono::seconds{15}) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    return predicate();
}

}  // namespace

TEST(QuicLink, KernelModeReturnsNotImplemented) {
    auto t = std::make_shared<QuicLink>();
    EXPECT_EQ(t->listen("quic://127.0.0.1:0"), GN_ERR_NOT_IMPLEMENTED);
    EXPECT_EQ(t->connect("quic://127.0.0.1:0"), GN_ERR_NOT_IMPLEMENTED);
}

TEST(QuicLink, ComposerListenWithoutHostApiReturnsInvalidState) {
    auto t = std::make_shared<QuicLink>();
    EXPECT_EQ(t->composer_listen("quic://127.0.0.1:0"),
              GN_ERR_INVALID_STATE);
}

TEST(QuicLink, ComposerBadSchemeReturnsInvalidEnvelope) {
    auto t = std::make_shared<QuicLink>();
    EXPECT_EQ(t->composer_listen("tcp://127.0.0.1:0"),
              GN_ERR_INVALID_ENVELOPE);
    gn_conn_id_t out = GN_INVALID_ID;
    EXPECT_EQ(t->composer_connect("quac://127.0.0.1:1", &out),
              GN_ERR_INVALID_ENVELOPE);
}

TEST(QuicLink, SubscribeDataRejectsKernelManagedConn) {
    auto t = std::make_shared<QuicLink>();
    EXPECT_EQ(t->composer_subscribe_data(
        42, [](void*, gn_conn_id_t, const std::uint8_t*, std::size_t) {},
        nullptr), GN_ERR_NOT_FOUND);
}

TEST(QuicLink, ListenPortBeforeCarrier) {
    auto t = std::make_shared<QuicLink>();
    std::uint16_t p = 0xBEEF;
    EXPECT_EQ(t->composer_listen_port(&p), GN_ERR_INVALID_STATE);
    EXPECT_EQ(p, 0u);
}

TEST(QuicLink, AcceptSubscriptionRoundtrip) {
    auto t = std::make_shared<QuicLink>();
    gn_subscription_id_t token = GN_INVALID_SUBSCRIPTION_ID;
    EXPECT_EQ(t->composer_subscribe_accept(
        [](void*, gn_conn_id_t, const char*) {}, nullptr, &token), GN_OK);
    EXPECT_NE(token, GN_INVALID_SUBSCRIPTION_ID);
    EXPECT_EQ(t->composer_unsubscribe_accept(token), GN_OK);
    EXPECT_EQ(t->composer_unsubscribe_accept(token), GN_OK);
}

TEST(QuicLink, CapabilitiesAdvertiseStreamReliableOrderedEncrypted) {
    const auto caps = QuicLink::capabilities();
    EXPECT_TRUE(caps.flags & GN_LINK_CAP_STREAM);
    EXPECT_TRUE(caps.flags & GN_LINK_CAP_RELIABLE);
    EXPECT_TRUE(caps.flags & GN_LINK_CAP_ORDERED);
    EXPECT_TRUE(caps.flags & GN_LINK_CAP_ENCRYPTED_PATH);
}

// ── Carrier scheme detection (Q.1) ────────────────────────────────────

constexpr const char* kPeerPkHex64 =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// `quic://<64 hex chars>` MUST route through the ICE carrier
/// (`gn.link.ice`). Without an ICE bridge in the harness the
/// query falls through to NOT_FOUND — that itself proves
/// `detect_carrier_scheme` picked `"ice"` over `"udp"`, because
/// the harness does expose `gn.link.udp` so a UDP-routed connect
/// would have succeeded against it.
TEST(QuicLink, ComposerConnectIcePeerPkRoutesToIceCarrier) {
    QuicHarness harness;
    auto api = harness.make_api();
    harness.udp_bridge.udp->set_host_api(&api);

    auto t = std::make_shared<QuicLink>();
    t->set_host_api(&api);
    t->set_verify_peer(false);

    const std::string uri = std::string("quic://") + kPeerPkHex64;
    gn_conn_id_t out = GN_INVALID_ID;
    /// No `gn.link.ice` in the harness yet → ensure_carrier fails
    /// with NOT_FOUND, distinct from the INVALID_ENVELOPE path that
    /// malformed URIs follow.
    EXPECT_EQ(t->composer_connect(uri, &out), GN_ERR_NOT_FOUND);
    EXPECT_EQ(out, GN_INVALID_ID);
    t->shutdown();
}

/// `quic://<host:port>` continues to route through the UDP carrier
/// — the detection only switches on the 64-hex shape.
TEST(QuicLink, ComposerConnectHostPortStillRoutesUdp) {
    QuicHarness harness;
    auto api = harness.make_api();
    harness.udp_bridge.udp->set_host_api(&api);

    auto t = std::make_shared<QuicLink>();
    t->set_host_api(&api);
    t->set_verify_peer(false);

    gn_conn_id_t out = GN_INVALID_ID;
    /// UDP bridge is wired in the harness; `composer_connect` should
    /// reach the carrier and return the bridged success.
    EXPECT_EQ(t->composer_connect("quic://127.0.0.1:9999", &out), GN_OK);
    EXPECT_NE(out, GN_INVALID_ID);
    EXPECT_TRUE(out & QuicLink::kComposerIdBit);
    t->shutdown();
}

/// With the ICE bridge enabled in the harness, a `quic://<64-hex>`
/// URI must allocate a composer cid by reaching IceLink through the
/// extension surface — proves the full QUIC → ICE composer chain
/// works end-to-end at the surface level. ICE's `composer_connect`
/// returns OK once it has validated the URI and posted a gather
/// (no real nomination because there's no real signaling exchange
/// in this fixture; that gap is what blocks the deeper handshake
/// test from running here).
TEST(QuicLink, ComposerConnectIceWithBridgeAllocatesCid) {
    QuicHarness harness;
    auto api = harness.make_api();
    harness.udp_bridge.udp->set_host_api(&api);
    /// `api` lives on the test's stack; enabling the ICE bridge
    /// AFTER the api is created lets IceLink share the same
    /// `host_api_t` pointer through its lifetime.
    harness.enable_ice(&api);

    auto t = std::make_shared<QuicLink>();
    t->set_host_api(&api);
    t->set_verify_peer(false);

    const std::string uri = std::string("quic://") + kPeerPkHex64;
    gn_conn_id_t out = GN_INVALID_ID;
    ASSERT_EQ(t->composer_connect(uri, &out), GN_OK);
    EXPECT_NE(out, GN_INVALID_ID);
    EXPECT_TRUE(out & QuicLink::kComposerIdBit);
    t->shutdown();
    harness.ice_bridge->ice->shutdown();
}

/// Listener-pattern smoke (BIO_dgram_pair + SSL_new_listener + ALPN
/// + SSL_set1_initial_peer_addr): the QUIC state machine advances
/// through ClientHello processing — packets fly in both directions,
/// ALPN selects "gn-v1", server reaches `TLS_ST_EARLY_DATA`, client
/// reaches `TLS_ST_CW_CLNT_HELLO` and stays there. Stuck point:
/// BIO_write on the receiving network BIO loses the original
/// sender's src address (memory-pair forward uses the receiving
/// BIO's default peer), so the receiving SSL sees every datagram
/// as coming from `127.0.0.1:1` rather than the real
/// peer. QUIC connection routing then can't reassemble the handshake
/// fragments under the correct (local, peer) tuple.
///
/// Next iteration (deferred): replace plain BIO_read/BIO_write at the
/// drain/feed boundary with `BIO_sendmmsg`/`BIO_recvmmsg` so the per-
/// datagram src/dst metadata crosses the user-space carrier intact.
/// Or: switch to `BIO_dgram_mem` (single-ended) and manage messages
/// manually with explicit BIO_msghdr_t.
TEST(QuicComposer, HandshakeAndPayloadRoundTrip) {
    /// Two separate UdpLink instances so the loopback datagrams flow
    /// between distinct sockets — same pattern as `test_dtls.cpp`.
    QuicHarness server_harness;
    QuicHarness client_harness;
    auto server_api = server_harness.make_api();
    auto client_api = client_harness.make_api();
    server_harness.udp_bridge.udp->set_host_api(&server_api);
    client_harness.udp_bridge.udp->set_host_api(&client_api);
    /// QUIC Initial + handshake packets can exceed the default UDP MTU
    /// of 1200 bytes when the server's cert is large; raise the cap
    /// for the loopback test the same way DTLS does. Real deployments
    /// use a smaller cert or rely on QUIC handshake fragmentation.
    server_harness.udp_bridge.udp->set_mtu(65000);
    client_harness.udp_bridge.udp->set_mtu(65000);

    auto server = std::make_shared<QuicLink>();
    auto client = std::make_shared<QuicLink>();

    std::string cert_pem, key_pem;
    ASSERT_TRUE(gn::tests::support::generate_self_signed(cert_pem, key_pem));
    server->set_server_credentials(cert_pem, key_pem);
    server->set_host_api(&server_api);
    server->set_verify_peer(false);

    client->set_host_api(&client_api);
    client->set_verify_peer(false);

    AcceptRecorder accept_rec;
    gn_subscription_id_t accept_token = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(server->composer_subscribe_accept(&AcceptRecorder::thunk,
                                                  &accept_rec,
                                                  &accept_token), GN_OK);

    ASSERT_EQ(server->composer_listen("quic://127.0.0.1:0"), GN_OK);
    std::uint16_t server_port = 0;
    ASSERT_EQ(server->composer_listen_port(&server_port), GN_OK);
    ASSERT_GT(server_port, 0u);

    const std::string uri =
        "quic://127.0.0.1:" + std::to_string(server_port);
    gn_conn_id_t client_conn = GN_INVALID_ID;
    ASSERT_EQ(client->composer_connect(uri, &client_conn), GN_OK);
    EXPECT_NE(client_conn, GN_INVALID_ID);
    EXPECT_TRUE(client_conn & QuicLink::kComposerIdBit);

    DataRecorder client_rec;
    ASSERT_EQ(client->composer_subscribe_data(client_conn,
                                                &DataRecorder::thunk,
                                                &client_rec), GN_OK);

    ASSERT_TRUE(wait_for([&] {
        return accept_rec.count.load() >= 1;
    })) << "QUIC handshake did not complete within timeout";

    const gn_conn_id_t server_conn =
        accept_rec.last.load(std::memory_order_acquire);
    ASSERT_NE(server_conn, GN_INVALID_ID);
    EXPECT_TRUE(server_conn & QuicLink::kComposerIdBit);

    DataRecorder server_rec;
    ASSERT_EQ(server->composer_subscribe_data(server_conn,
                                                &DataRecorder::thunk,
                                                &server_rec), GN_OK);

    const std::vector<std::uint8_t> from_client{0x11, 0x22, 0x33};
    const std::vector<std::uint8_t> from_server{0xAA, 0xBB, 0xCC, 0xDD};

    ASSERT_EQ(client->send(client_conn,
        std::span<const std::uint8_t>(from_client)), GN_OK);
    ASSERT_EQ(server->send(server_conn,
        std::span<const std::uint8_t>(from_server)), GN_OK);

    ASSERT_TRUE(wait_for([&] {
        return server_rec.count.load() >= 1 &&
               client_rec.count.load() >= 1;
    })) << "QUIC payload did not surface in both directions";

    {
        std::lock_guard lk(server_rec.mu);
        ASSERT_FALSE(server_rec.frames.empty());
        EXPECT_EQ(server_rec.frames.front(), from_client);
    }
    {
        std::lock_guard lk(client_rec.mu);
        ASSERT_FALSE(client_rec.frames.empty());
        EXPECT_EQ(client_rec.frames.front(), from_server);
    }

    EXPECT_EQ(server->composer_unsubscribe_accept(accept_token), GN_OK);
    server->shutdown();
    client->shutdown();
    server_harness.udp_bridge.udp->shutdown();
    client_harness.udp_bridge.udp->shutdown();
}
