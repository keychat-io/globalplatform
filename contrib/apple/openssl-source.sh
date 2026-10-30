# Shared pinned source for the build and host checks. Source this file from bash.
OPENSSL_VERSION=3.5.9
OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
DOWNLOADS="$BUILD_ROOT/downloads"
ARCHIVE="$DOWNLOADS/openssl-$OPENSSL_VERSION.tar.gz"
mkdir -p "$DOWNLOADS"
if [[ ! -f "$ARCHIVE" ]]; then
  curl --fail --location --retry 2 "https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz" -o "$ARCHIVE"
fi
printf '%s  %s\n' "$OPENSSL_SHA256" "$ARCHIVE" | shasum -a 256 -c -
if [[ ! -d "$DOWNLOADS/openssl-$OPENSSL_VERSION" ]]; then
  tar -xzf "$ARCHIVE" -C "$DOWNLOADS"
fi
OPENSSL_SOURCE="$DOWNLOADS/openssl-$OPENSSL_VERSION"
