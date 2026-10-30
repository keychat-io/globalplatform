# Apple static callback build

This profile builds the SDK and a pinned OpenSSL for arm64 iPhoneOS and arm64
Simulator, with iOS 18.0 as the deployment target. It does not install an app or
communicate with a card. The regular desktop PC/SC build remains the default.

Requirements: macOS on Apple Silicon, full Xcode with iPhoneOS/Simulator SDKs,
CMake 3.13+, make, Perl, curl, Git, and the standard macOS command-line tools.
Select the intended Xcode with `xcode-select` before building.

```sh
./contrib/apple/build-apple.sh
# Or select a single platform:
./contrib/apple/build-apple.sh iphonesimulator
# Native ASan SDK checks, provider failure injection, and DES/AES known answers:
./contrib/apple/test-host.sh
```

The default download/build root is `contrib/apple/.build/` and is ignored by Git.
Set `GP_BUILD_ROOT` to an absolute path to keep artifacts elsewhere; set
`GP_BUILD_JOBS` to adjust parallelism (default 8). No Homebrew OpenSSL or PC/SC
compatibility headers are used. The host checks also build the pinned OpenSSL.
The scripts verify the source archive SHA256 before extraction; use a fresh
build root if the extracted dependency source has been modified.

OpenSSL 3.5.9 is pinned to SHA256
`603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a`.
This was the current 3.5 LTS patch listed by the
[official download page](https://openssl-library.org/source/) on 2026-10-30.
The archive is fetched from the official release URL and the checksum is fixed
in `openssl-source.sh`. This is a reproducible dependency pin, not an assurance
that future releases or security advisories need no review.

OpenSSL uses `no-shared no-module no-dso`, including its legacy provider in the
static archive for SDK DES operations. Its libraries and headers are built
separately for the device and Simulator SDKs; host OpenSSL headers are not used
for the iOS targets. System zlib comes from the selected Apple SDK.

## SDK profile and lifetime

The equivalent SDK CMake options are:

```sh
-DSTATIC=ON -DTOOLS=OFF -DGLOBALPLATFORM_WITH_PCSC=OFF \
-DGLOBALPLATFORM_STATIC_CALLBACKS=ON
```

Static callbacks require those three accompanying settings; inconsistent
combinations fail configuration. PC/SC discovery, the PC/SC plugin and the
SDK dynamic plugin loader are excluded. Logging is forced off for this profile:
SDK debug functions and `OPGP_enable_trace_mode` remain callable but produce no
output. `GLOBALPLATFORM_DEBUG` cannot re-enable them.

Use the existing SDK callback contract:

1. Zero-initialize `OPGP_CARD_CONTEXT` and `OPGP_CARD_INFO`.
2. Set `context.connectionFunctions.sendAPDU` and the caller-owned
   `context.librarySpecific`. Set any lifecycle/reader callbacks that will be
   used. `libraryHandle` must remain NULL.
3. Call `OPGP_establish_context(&context)` and check the returned status before
   issuing command APIs. Establishment preserves the supplied callbacks and
   explicitly initializes crypto; it does not load a transport plugin.
4. Serialize exchanges in the transport implementation, retain all callback
   state until in-flight exchanges have drained, then release the context.

This profile has a fixed-width callback ABI: BYTE is 8 bits, USHORT 16 bits,
DWORD 32 bits, and LONG/BOOL signed 32 bits. CMake exports `OPGP_NO_PCSC`,
`OPGP_STATIC_CALLBACKS`, `OPGP_NO_LOGGING` and `OPGP_STATIC` to consumers. Use
these definitions if consuming the C headers without the installed CMake target;
never mix this ABI with structures built using another PC/SC profile.

OpenSSL 3 default/legacy providers initialize once, in a thread-safe path reached
from context establishment. Initialization failure returns `OPGP_ERROR_CRYPT`
and remains a failure on later attempts; it does not terminate the application.
The callback profile has no SDK constructor/destructor and does not call global
`OPENSSL_cleanup`. Provider handles have process lifetime, independent of card
contexts. Direct command calls that bypass successful establishment violate
this initialization contract. Applications must not globally clean up the same
libcrypto instance while the SDK may still be used.

The synchronous callback interface does not by itself provide Core NFC bridging,
cancellation, asynchronous ownership checks or in-flight draining. No such
adapter is included here.

## Evidence and artifacts

Each platform produces `out/<platform>/sdk` and `out/<platform>/openssl`, plus:

- Ordinary and whole-SDK static consumer links. The second uses `-force_load`
  to expose unresolved references throughout the SDK, rather than only the
  functions reached by a minimal example.
- `link-platform.txt`, `link-dependencies.txt`, and `link-undefined.txt`, recording
  deployment platform/minimum, linked dylibs and unresolved system symbols.
  The script fails if the linked consumer references the SDK loader or SCard APIs.
- Version, base commit, tracked local patch, public-header and artifact checksums.
- `licenses/`, including OpenSSL, the SDK LGPL/GPL texts and OpenSSL exception,
  and the bundled minizip notice.
- Platform archives under `out/` with static libraries, public headers, license
  records and the linked consumer binaries in `proof/`. Run
  `shasum -a 256 -c artifact-sha256.txt` from an extracted platform directory.
- Source archives and checksums under `out/`, containing the patched SDK with
  its build helpers and the exact OpenSSL source archive.

The iOS scripts compile and link both consumers; they do not execute them.
The host checks execute ordinary and whole-SDK consumers, test 0/1-byte and
above-capacity callback response lengths in ordinary/short-chain/extended send
paths, check a transport failure is not replayed, test inert logging, execute
DES/AES known-answer encryption, and inject provider-discovery failure into a
separately compiled initialization object. They also run the offline registry
CTest target and static-callback crypto response-boundary target. This does not establish secure-channel interoperability, real-card
support or asynchronous transport correctness.

`OPGP_send_APDU` and both chained transport branches now reject callback-reported
response lengths below two bytes or above the original supplied capacity before
logging/unwrapping. This applies to all SDK profiles. A callback must still honor
the buffer capacity while writing; a reported-length check cannot repair an
out-of-bounds write performed inside the callback.

## License records

The SDK source notices specify LGPL-3.0-or-later and retain an OpenSSL linking
exception. `COPYING.LESSER` incorporates the GPL v3 text from the repository's
`COPYING`. OpenSSL 3.5.9's `LICENSE.txt` is Apache-2.0. The bundled minizip code
carries its own notice in the source headers.

LGPL v3 section 4 describes notices and license copies for combined works, and
section 4(d)(0) describes the source/application-code path that permits
recombining or relinking with a modified library when using static linkage.
Section 4(e) addresses Installation Information when GPL v3 section 6 would
require it. The included build/source records preserve inputs for that work;
these build probes do not produce a release compliance package, corresponding
application objects, signing access or a determination about an App Store
distribution. Refer to the included license texts when preparing a distribution.

## Secure-channel compatibility gate

The independent probe in `../qualification/` passes SCP02 i=55 and SCP03 S8
random/pseudo-random authentication plus a protected issuer read against the
CardPress pyca peer. The current SDK's SCP03 authentication still sends an
eight-byte host challenge, so both SCP03 S16 modes fail that compatibility gate.
Do not treat this platform/registry foundation as a complete replacement for a
backend that already supports S16. No automatic downgrade is authorized.
