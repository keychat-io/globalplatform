#!/bin/bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SDK_SOURCE=$(cd "$SCRIPT_DIR/../.." && pwd)
BUILD_ROOT=${GP_BUILD_ROOT:-$SCRIPT_DIR/.build}
. "$SCRIPT_DIR/openssl-source.sh"
SOURCE="$OPENSSL_SOURCE"
PREFIX="$BUILD_ROOT/out/host"
JOBS=${GP_BUILD_JOBS:-8}
mkdir -p "$PREFIX/openssl-build"
(
  cd "$PREFIX/openssl-build"
  env -u CFLAGS -u CPPFLAGS -u LDFLAGS -u LIBRARY_PATH -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH \
    "$SOURCE/Configure" darwin64-arm64-cc no-shared no-module no-dso no-tests no-apps no-docs \
    --prefix="$PREFIX/openssl" --libdir=lib
  make -j "$JOBS"
  make install_sw
) > "$PREFIX/openssl-build.log" 2>&1
cmake -S "$SDK_SOURCE" -B "$PREFIX/sdk-build" -DSTATIC=ON -DTOOLS=OFF \
  -DGLOBALPLATFORM_WITH_PCSC=OFF -DGLOBALPLATFORM_STATIC_CALLBACKS=ON \
  -DGLOBALPLATFORM_ENABLE_ASAN=ON -DTESTING=ON -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_INSTALL_PREFIX="$PREFIX/sdk" -DOPENSSL_ROOT_DIR="$PREFIX/openssl" \
  -DOPENSSL_USE_STATIC_LIBS=TRUE -DOPENSSL_INCLUDE_DIR="$PREFIX/openssl/include" \
  -DOPENSSL_CRYPTO_LIBRARY="$PREFIX/openssl/lib/libcrypto.a" \
  -DOPENSSL_SSL_LIBRARY="$PREFIX/openssl/lib/libssl.a" > "$PREFIX/sdk-configure.log" 2>&1
cmake --build "$PREFIX/sdk-build" --parallel "$JOBS" > "$PREFIX/sdk-build.log" 2>&1
cmake --install "$PREFIX/sdk-build" > "$PREFIX/sdk-install.log" 2>&1
ctest --test-dir "$PREFIX/sdk-build" -R '^(registryIntegrityTest|cryptoResponseBoundsTest)$' --output-on-failure
cmake -S "$SCRIPT_DIR/consumer" -B "$PREFIX/consumer-build" \
  -Dglobalplatform_DIR="$PREFIX/sdk/lib/cmake/globalplatform" \
  -DOPENSSL_ROOT_DIR="$PREFIX/openssl" -DOPENSSL_USE_STATIC_LIBS=TRUE \
  -DOPENSSL_INCLUDE_DIR="$PREFIX/openssl/include" \
  -DOPENSSL_CRYPTO_LIBRARY="$PREFIX/openssl/lib/libcrypto.a" \
  -DOPENSSL_SSL_LIBRARY="$PREFIX/openssl/lib/libssl.a" > "$PREFIX/consumer-configure.log" 2>&1
cmake --build "$PREFIX/consumer-build" --parallel "$JOBS" > "$PREFIX/consumer-build.log" 2>&1
"$PREFIX/consumer-build/gp_callback_smoke_normal"
"$PREFIX/consumer-build/gp_callback_smoke"
cc -fsanitize=address,undefined -g -DOPGP_NO_PCSC -DOPGP_STATIC_CALLBACKS -DOPGP_STATIC \
  -DOSSL_PROVIDER_load=gp_test_provider_load -I"$SDK_SOURCE/globalplatform/src" \
  -I"$PREFIX/openssl/include" "$SDK_SOURCE/globalplatform/src/init.c" \
  "$SCRIPT_DIR/consumer/crypto-init-failure.c" "$PREFIX/openssl/lib/libcrypto.a" \
  -o "$PREFIX/provider-failure"
"$PREFIX/provider-failure"
