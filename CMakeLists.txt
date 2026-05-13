cmake_minimum_required(VERSION 3.22)

if(NOT TARGET GoodNet::sdk)
    project(goodnet_link_quic
        VERSION   1.0.0
        LANGUAGES CXX)
    find_package(GoodNet REQUIRED)
    include(CTest)
    if(BUILD_TESTING)
        find_package(GTest      REQUIRED)
        find_package(rapidcheck QUIET)
        goodnet_patch_rapidcheck_targets()
        set(GOODNET_BUILD_TESTS ON)
    endif()
endif()

# QUIC transport plugin — Apache 2.0.
# Uses OpenSSL 3.6+ native QUIC API (OSSL_QUIC_server_method /
# OSSL_QUIC_client_method + SSL_new_listener / SSL_new_stream). The
# plugin sits on top of UDP carrier via LinkCarrier pattern, same
# shape as TLS-on-TCP and DTLS-on-UDP (5d). Per-connection ComposerSession
# drives the SSL state machine through a BIO_pair pump; encrypted bytes
# go out via the carrier, decrypted application bytes flow up through
# the composer data subscribers.

add_library(goodnet_quic_objects OBJECT
    quic.cpp
    quic_composer_session.cpp
)
target_link_libraries(goodnet_quic_objects PUBLIC
    GoodNet::sdk asio::asio Threads::Threads
    OpenSSL::SSL OpenSSL::Crypto)
target_compile_features(goodnet_quic_objects PUBLIC cxx_std_23)
target_compile_options(goodnet_quic_objects PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter)
target_include_directories(goodnet_quic_objects PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(goodnet_quic_objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

add_plugin(goodnet_link_quic
    plugin_entry.cpp
)
target_link_libraries(goodnet_link_quic
    PRIVATE goodnet_quic_objects asio::asio Threads::Threads
            OpenSSL::SSL OpenSSL::Crypto)

if(GOODNET_BUILD_TESTS)
    add_subdirectory(tests)
endif()
