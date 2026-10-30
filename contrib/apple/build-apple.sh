#!/bin/bash
# Rebuild the pinned OpenSSL and callback-only SDK; do not install or run on a device.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SDK_SOURCE=$(cd "$SCRIPT_DIR/../.." && pwd)
BUILD_ROOT=${GP_BUILD_ROOT:-$SCRIPT_DIR/.build}
MIN_IOS=18.0
JOBS=${GP_BUILD_JOBS:-8}
. "$SCRIPT_DIR/openssl-source.sh"
OUT="$BUILD_ROOT/out"
mkdir -p "$OUT"
if [[ $# -eq 0 ]]; then set -- iphoneos iphonesimulator; fi
for PLATFORM in "$@"; do
    case "$PLATFORM" in
      iphoneos) TARGET=ios64-xcrun; TRIPLE=arm64-apple-ios$MIN_IOS ;;
      iphonesimulator) TARGET=iossimulator-arm64-xcrun; TRIPLE=arm64-apple-ios$MIN_IOS-simulator ;;
      *) printf 'Unsupported SDK: %s\n' "$PLATFORM" >&2; exit 2 ;;
    esac
    SYSROOT=$(xcrun --sdk "$PLATFORM" --show-sdk-path)
    PREFIX="$OUT/$PLATFORM"
    CRYPTO_BUILD="$PREFIX/openssl-build"
    CRYPTO_INSTALL="$PREFIX/openssl"
    GP_BUILD="$PREFIX/sdk-build"
    GP_INSTALL="$PREFIX/sdk"
    mkdir -p "$CRYPTO_BUILD" "$CRYPTO_INSTALL" "$GP_BUILD" "$GP_INSTALL"
    (
      cd "$CRYPTO_BUILD"
      env -u CPPFLAGS -u LDFLAGS -u LIBRARY_PATH -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH \
        CFLAGS="-O3 -target $TRIPLE -isysroot $SYSROOT" "$OPENSSL_SOURCE/Configure" "$TARGET" no-shared no-module no-dso no-tests no-apps no-docs \
        --prefix="$CRYPTO_INSTALL" --openssldir="$CRYPTO_INSTALL/ssl" --libdir=lib
      make -j "$JOBS"
      make install_sw
    ) > "$PREFIX/openssl-build.log" 2>&1
    cmake -S "$SDK_SOURCE" -B "$GP_BUILD" \
      -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_SYSROOT="$PLATFORM" -DCMAKE_OSX_ARCHITECTURES=arm64 \
      -DCMAKE_OSX_DEPLOYMENT_TARGET="$MIN_IOS" -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX="$GP_INSTALL" -DSTATIC=ON -DTOOLS=OFF \
      -DGLOBALPLATFORM_WITH_PCSC=OFF -DGLOBALPLATFORM_STATIC_CALLBACKS=ON \
      -DGLOBALPLATFORM_ENABLE_ASAN=OFF -DTESTING=OFF -DGLOBALPLATFORM_BUILD_DOCS=OFF \
      -DOPENSSL_ROOT_DIR="$CRYPTO_INSTALL" -DOPENSSL_USE_STATIC_LIBS=TRUE \
      -DOPENSSL_INCLUDE_DIR="$CRYPTO_INSTALL/include" \
      -DOPENSSL_CRYPTO_LIBRARY="$CRYPTO_INSTALL/lib/libcrypto.a" \
      -DOPENSSL_SSL_LIBRARY="$CRYPTO_INSTALL/lib/libssl.a" \
      > "$PREFIX/sdk-configure.log" 2>&1
    cmake --build "$GP_BUILD" --parallel "$JOBS" > "$PREFIX/sdk-build.log" 2>&1
    cmake --install "$GP_BUILD" > "$PREFIX/sdk-install.log" 2>&1
    # Consume the installed CMake package, proving its public ABI definitions and dependencies.
    cmake -S "$SCRIPT_DIR/consumer" -B "$PREFIX/consumer-build" \
      -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_SYSROOT="$PLATFORM" -DCMAKE_OSX_ARCHITECTURES=arm64 \
      -DCMAKE_OSX_DEPLOYMENT_TARGET="$MIN_IOS" -DCMAKE_BUILD_TYPE=Release \
      -Dglobalplatform_DIR="$GP_INSTALL/lib/cmake/globalplatform" \
      -DOPENSSL_ROOT_DIR="$CRYPTO_INSTALL" -DOPENSSL_USE_STATIC_LIBS=TRUE \
      -DOPENSSL_INCLUDE_DIR="$CRYPTO_INSTALL/include" \
      -DOPENSSL_CRYPTO_LIBRARY="$CRYPTO_INSTALL/lib/libcrypto.a" \
      -DOPENSSL_SSL_LIBRARY="$CRYPTO_INSTALL/lib/libssl.a" \
      > "$PREFIX/consumer-configure.log" 2>&1
    cmake --build "$PREFIX/consumer-build" --parallel "$JOBS" > "$PREFIX/consumer-build.log" 2>&1
    BINARY="$PREFIX/consumer-build/gp_callback_smoke"
    xcrun vtool -show-build "$BINARY" > "$PREFIX/link-platform.txt"
    xcrun otool -L "$BINARY" > "$PREFIX/link-dependencies.txt"
    xcrun nm -u "$BINARY" > "$PREFIX/link-undefined.txt"
    if grep -E '_(dlopen|dlsym|dlclose|SCard[A-Za-z_]+)$' "$PREFIX/link-undefined.txt"; then
      printf 'Unexpected plugin/PCSC dependency\n' >&2; exit 1
    fi
    mkdir -p "$PREFIX/licenses"
    cp "$OPENSSL_SOURCE/LICENSE.txt" "$PREFIX/licenses/OpenSSL-LICENSE.txt"
    cp "$SDK_SOURCE/COPYING" "$PREFIX/licenses/GlobalPlatform-COPYING-GPL3.txt"
    cp "$SDK_SOURCE/LICENSE.OpenSSL" "$PREFIX/licenses/GlobalPlatform-OpenSSL-exception.txt"
    cp "$SDK_SOURCE/globalplatform/src/unzip/unzip.h" "$PREFIX/licenses/Minizip-notice.h"
    cp "$SDK_SOURCE/globalplatform/LICENSE" "$PREFIX/licenses/GlobalPlatform-LICENSE.txt"
    cp "$SDK_SOURCE/globalplatform/COPYING.LESSER" "$PREFIX/licenses/GlobalPlatform-COPYING.LESSER.txt"
    git -C "$SDK_SOURCE" rev-parse HEAD > "$PREFIX/SDK-BASE-COMMIT.txt"
    git -C "$SDK_SOURCE" diff --binary > "$PREFIX/SDK-LOCAL-PATCH.diff"
    printf 'OpenSSL=%s\nOpenSSL-SHA256=%s\nSDK=%s\nTarget=%s\nMinimum-iOS=%s\n' \
      "$OPENSSL_VERSION" "$OPENSSL_SHA256" "$PLATFORM" "$TRIPLE" "$MIN_IOS" > "$PREFIX/VERSIONS.txt"
    xcodebuild -version >> "$PREFIX/VERSIONS.txt"
    xcrun --sdk "$PLATFORM" --show-sdk-version >> "$PREFIX/VERSIONS.txt"
    mkdir -p "$PREFIX/proof"
    cp "$BINARY" "$PREFIX/consumer-build/gp_callback_smoke_normal" "$PREFIX/proof/"
    (cd "$PREFIX" && find sdk/include -type f -exec shasum -a 256 {} \;) > "$PREFIX/public-header-sha256.txt"
    (cd "$PREFIX" && shasum -a 256 proof/gp_callback_smoke proof/gp_callback_smoke_normal \
      sdk/lib/libglobalplatform.a openssl/lib/libcrypto.a) > "$PREFIX/artifact-sha256.txt"
    tar -czf "$OUT/globalplatform-$PLATFORM-arm64.tar.gz" -C "$PREFIX" \
      sdk openssl licenses proof VERSIONS.txt SDK-BASE-COMMIT.txt SDK-LOCAL-PATCH.diff \
      artifact-sha256.txt public-header-sha256.txt link-platform.txt link-dependencies.txt link-undefined.txt
    printf 'PASS full static SDK link: %s (%s)\n' "$PLATFORM" "$BINARY"
done
# Package the complete local source, including untracked build helpers. The
# output/cache is ignored and excluded; no .git metadata or credentials are copied.
(
  cd "$SDK_SOURCE"
  git ls-files --cached --others --exclude-standard -z |
    tar --null -T - -czf "$OUT/globalplatform-patched-source.tar.gz"
)
cp "$ARCHIVE" "$OUT/openssl-$OPENSSL_VERSION-source.tar.gz"
(cd "$OUT" && shasum -a 256 globalplatform-patched-source.tar.gz \
  "openssl-$OPENSSL_VERSION-source.tar.gz") > "$OUT/source-sha256.txt"
(cd "$OUT" && shasum -a 256 globalplatform-*-arm64.tar.gz) > "$OUT/package-sha256.txt"
