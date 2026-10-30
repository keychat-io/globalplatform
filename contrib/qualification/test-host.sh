#!/bin/bash
# Card-free real-library regression; synthetic fixtures only.
set -euo pipefail
sdk_root="$(cd "$(dirname "$0")/../.." && pwd)"
peer="${1:?Usage: test-host.sh /absolute/path/to/gp_card_peer.py [build-directory]}"
out="${2:-$sdk_root/out/build/qualification}"
openssl_root="${OPENSSL_ROOT_DIR:-/opt/homebrew/opt/openssl@3}"
python_bin="${PYTHON_BIN:-python3}"
if [[ ! -f "$peer" || ! -f "$openssl_root/lib/libcrypto.a" ]]; then
  echo "A readable independent peer and host OpenSSL static installation are required." >&2
  exit 1
fi
for profile in normal sanitized; do
  flags=(-Wno-deprecated-declarations)
  build_type=Release
  if [[ "$profile" == sanitized ]]; then
    flags+=(-fsanitize=address,undefined -fno-sanitize-recover=all -g)
    build_type=Debug
  fi
  build="$out/$profile"
  cmake -S "$sdk_root" -B "$build" -DSTATIC=ON -DTOOLS=OFF \
    -DGLOBALPLATFORM_WITH_PCSC=OFF -DGLOBALPLATFORM_STATIC_CALLBACKS=ON \
    -DGLOBALPLATFORM_ENABLE_ASAN=OFF -DTESTING=ON -DCMAKE_BUILD_TYPE="$build_type" \
    -DCMAKE_C_FLAGS="${flags[*]}" -DOPENSSL_ROOT_DIR="$openssl_root" -DOPENSSL_USE_STATIC_LIBS=TRUE
  cmake --build "$build" --parallel "${GP_BUILD_JOBS:-8}"
  ctest --test-dir "$build" -LE integration --output-on-failure
  cc "${flags[@]}" -DOPGP_STATIC -DOPGP_STATIC_CALLBACKS -DOPGP_NO_PCSC \
    -I"$sdk_root/globalplatform/src" -I"$openssl_root/include" \
    "$sdk_root/contrib/qualification/auth_probe.c" \
    "$build/globalplatform/src/libglobalplatform.a" "$openssl_root/lib/libcrypto.a" -lz \
    -o "$build/auth_probe"
  "$python_bin" "$sdk_root/contrib/qualification/auth_peer.py" \
    --peer "$peer" --probe "$build/auth_probe" --full
done
