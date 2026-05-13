# Standalone Nix derivation for the goodnet-link-quic plugin.
# Pulls the kernel SDK + AddPlugin.cmake helper through `goodnet-core`'s
# `propagatedBuildInputs` (asio / libsodium / openssl / spdlog / fmt /
# nlohmann_json). `openssl` is also listed explicitly here because the
# QUIC plugin requires the native QUIC API shipped in OpenSSL 3.6 — if
# the kernel ever upgrades through a 3.5-pinned snapshot, the explicit
# entry surfaces the version mismatch at plugin build time instead of
# at link time.
{ stdenv
, cmake
, ninja
, pkg-config
, gtest
, rapidcheck
, openssl
, goodnet-core
, lib
}:

stdenv.mkDerivation {
  pname   = "goodnet-link-quic";
  version = "1.0.0-rc1";
  src     = ./.;
  nativeBuildInputs = [ cmake ninja pkg-config ];
  buildInputs       = [ goodnet-core gtest rapidcheck openssl ];
  cmakeFlags = [
    "-DCMAKE_BUILD_TYPE=Release"
    "-DBUILD_TESTING=OFF"
  ];
  doCheck = false;

  meta = {
    description = "GoodNet plugin: goodnet-link-quic";
    license = lib.licenses.asl20;
    platforms = lib.platforms.linux;
  };
}
