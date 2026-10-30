#!/bin/bash
# Card-free macOS host regression with real OpenSSL and ASan/UBSan.
# Usage: OPENSSL_ROOT_DIR=/path/to/openssl ./test-registry-host.sh [output-directory]
set -euo pipefail
sdk_root="$(cd "$(dirname "$0")/../.." && pwd)"
if [[ "$(uname -s)" != Darwin ]]; then
  echo "This host runner requires macOS and Xcode command-line tools." >&2
  exit 1
fi
openssl_root="${OPENSSL_ROOT_DIR:-/opt/homebrew/opt/openssl@3}"
if [[ ! -f "$openssl_root/lib/libcrypto.a" ]]; then
  echo "Set OPENSSL_ROOT_DIR to a host OpenSSL installation containing lib/libcrypto.a." >&2
  exit 1
fi
out="${1:-$(mktemp -d "${TMPDIR:-/tmp}/gp-registry-host.XXXXXX")}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
args=(-isysroot "$(xcrun --sdk macosx --show-sdk-path)" -I"$sdk_root/globalplatform/src" -I"$openssl_root/include" -DOPGP_STATIC -DOPGP_STATIC_CALLBACKS -DOPGP_NO_PCSC -DOPGP_NO_LOGGING -Wno-deprecated-declarations -fsanitize=address,undefined -fno-sanitize-recover=all -g)
objects=()
for source in connection stringify crypto loadfile util debug init globalplatform scp unzip/ioapi unzip/unzip; do
  injection=(-DGP_REGISTRY_TEST=1)
  if [[ "$source" == globalplatform ]]; then injection=(-Dcalloc=gp_registry_test_calloc -Drealloc=gp_registry_test_realloc -Dfree=gp_registry_test_free); fi
  object="$out/${source//\//_}.o"
  xcrun clang "${args[@]}" "${injection[@]}" -c "$sdk_root/globalplatform/src/$source.c" -o "$object"
  objects+=("$object")
done
# Explicit objects prevent accidentally including stale output from another build.
xcrun ar rcs "$out/libglobalplatform-registry-test.a" "${objects[@]}"
xcrun clang "${args[@]}" -DGP_REGISTRY_TEST_ALLOCATIONS "$sdk_root/globalplatform/src/registryIntegrityTest.c" "$out/libglobalplatform-registry-test.a" "$openssl_root/lib/libcrypto.a" -lz -o "$out/registryIntegrityTest"
# Apple Clang does not provide LeakSanitizer. Test allocator tracking separately
# asserts that all registry allocations are released on every injected failure.
ASAN_OPTIONS=detect_leaks=0 "$out/registryIntegrityTest"
printf 'Sanitized registry test output: %s\n' "$out"
