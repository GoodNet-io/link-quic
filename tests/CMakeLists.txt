# QUIC link plugin unit tests — Apache 2.0.
include(GoogleTest)

# The QUIC end-to-end test rides over a real UDP carrier exposed
# through the same TestCarrierBridge pattern as test_dtls.cpp. Builds
# only when goodnet_udp_objects is available so the dependency stays
# explicit at link time.
if(TARGET goodnet_udp_objects AND TARGET goodnet_ice_objects)
    add_executable(test_quic test_quic.cpp)
    target_link_libraries(test_quic PRIVATE
        GoodNet::sdk
        goodnet_quic_objects
        goodnet_udp_objects
        goodnet_ice_objects
        asio::asio
        Threads::Threads
        OpenSSL::SSL
        OpenSSL::Crypto
        PkgConfig::SODIUM
        GTest::gtest
        GTest::gtest_main)
    target_include_directories(test_quic PRIVATE
        ${CMAKE_SOURCE_DIR}/plugins/links/ice)
    target_compile_features(test_quic PRIVATE cxx_std_23)
    if(COMMAND goodnet_apply_pch)
        goodnet_apply_pch(test_quic)
    endif()
    gtest_discover_tests(test_quic
        DISCOVERY_TIMEOUT 30
        PROPERTIES TIMEOUT 60)
endif()
