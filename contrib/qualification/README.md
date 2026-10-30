# Independent SCP compatibility qualification

These card-free checks call the real SDK authentication and secure messaging APIs
against an external Python/pyca card peer. All keys and APDUs are synthetic.
They do not qualify an iPhone, an NFC transport, or a physical card.

## Protocol contract

SCP03 S8 and S16 use the existing SDK CMAC KDF and OpenSSL AES implementations.
Implementation bit `0x01` selects S16; bit `0x10` selects pseudo-random card
challenges. S16 uses 16-byte host/card challenges, authentication cryptograms,
and C-MACs; the chaining value remains the full 16-byte CMAC in either mode.
INITIALIZE UPDATE responses must have exactly the shape selected by these bits:
31/34 bytes for S8, or 47/50 for S16, including SW. Reserved option bits and
R-ENC without R-MAC capability are rejected. A supplied explicit option must
match the observed option. An S8 request never retries or upgrades to S16.

Both random and pseudo-random profiles are covered at security level `03`
(C-MAC plus C-ENC). Pseudo-random challenges are verified using the selected
invoking AID and three-byte sequence counter. Authentication comparisons use
OpenSSL's constant-time comparison. Failed authentication clears derived keys
and disables the returned session. Symmetric session keys are not logged.
The callback-only build additionally compiles out SDK logging.

S16 response MAC/encryption is **not qualified**. Authentication accepts levels
`00`, `01`, and `03`; S16 BEGIN R-MAC and response-protection helpers fail
explicitly. Existing S8 response-protection APIs remain available. The SDK's
32-bit encryption-counter representation is retained: case-1/case-2 commands
consume a counter, and exhaustion fails before an IV can be reused. The wider
S16 MAC is included in short/extended APDU capacity checks and LOAD block sizing.

Primary references:

- [GlobalPlatform Amendment D v1.2, GPC_SPE_014](https://globalplatform.org/specs-library/secure-channel-protocol-03-amendment-d-v1-2/),
  sections 4.1.5, 5.1, 6.2 and 7.1. No new cryptographic primitive is implemented.
- [GlobalPlatformPro S16 implementation, commit a807da1](https://github.com/martinpaljak/GlobalPlatformPro/commit/a807da1),
  independently consulted for option interpretation, KDF context, CMAC width,
  chaining and encryption-counter treatment. Its automatic retry policy is not
  adopted.
- [ETSI TS 102 226 v18.4.0, section 8.2.1.5.1](https://www.etsi.org/deliver/etsi_ts/102200_102299/102226/18.04.00_60/ts_102226v180400p.pdf):
  AES key blocks include the clear key length and pad only when needed to fill a
  cipher block. SCP03 key wrapping retains that length even for AES-128/256.

SCP02 case-1/case-2 commands retain the original absence of a command data field:
only the C-MAC is appended, with `Lc=08`. The implementation follows GP Card
Specification v2.3.1 section E.4.6 (encryption applies to the command data field,
excluding C-MAC) and the explicit `origLc > 0` condition in
[GlobalPlatformPro SCP02Wrapper](https://github.com/martinpaljak/GlobalPlatformPro/blob/master/library/src/main/java/pro/javacard/gp/SCP02Wrapper.java).
The C and independent wire tests assert this shape; a peer merely accepting
both forms is insufficient evidence to change it. SELECT also retains `Le=00`,
which is included in its transmitted length and checked by a capture test.

## Compatibility APIs

The existing public APIs and `GP211_SECURITY_INFO` layout are unchanged.

- `GP211_mutual_authentication_with_challenge` adds an optional caller challenge
  and length immediately before `secInfo`. `NULL, 0` invokes the SDK CSPRNG;
  explicit challenges must be fresh and exactly 8 or 16 bytes for the requested
  protocol/mode. Invalid lengths fail before transport. This allows deterministic
  independent tests without replacing the SDK's protocol implementation.
- `GP211_build_load_block` builds one short LOAD block without I/O or session
  mutation; the existing whole-buffer LOAD workflow uses the same builder. The
  caller owns payload planning and operation admission. The final block retains
  the SDK's `Le=00` behavior. Insufficient capacity reports the required size.
- `GP211_delete_application_ex` takes an explicit `deleteRelatedObjects` flag.
  False emits `P2=00`; true emits `P2=80`. The legacy API keeps `P2=80`.
  There is no scope expansion, fallback or retry. A delete token must have been
  signed for the selected scope.

The registry compatibility layer also exposes `GP211_parse_status_buffer` for
complete, bounded GET STATUS streams already assembled by a transport owner.
It performs no I/O and returns the same owned records as `GP211_get_status_ex`.
`privilegesLength` preserves the original C5 length. GET STATUS accepts a bounded
assembled callback response rather than imposing a single short-response limit;
legacy load-file RFU bytes must remain zero. See the public header for limits and
ownership, and `test-registry-host.sh` for allocator/failure regressions.

## Run the gates

`globalplatform/src/scp03S16Test.c` is a dependency-free offline CTest target.
It covers independent pyca KDF fixtures for AES-128/192/256, every implementation
option byte, valid and invalid response lengths, short APDU/capacity boundaries,
counter overflow, local input failures without APDUs, LOAD framing/workflow,
scoped DELETE without retry and AES key block lengths. Assertions remain enabled
in Release builds. A shared desktop build compiles internal helpers directly
into this test rather than exporting them from the shared ABI.

On a macOS host with OpenSSL and Python/pyca dependencies installed:

```sh
PYTHON_BIN=/path/to/python-with-cryptography \
  ./contrib/qualification/test-host.sh \
  /path/to/cardpress/core/tests/support/gp_card_peer.py
```

The runner performs ordinary Release and ASan/UBSan builds, CTests, and the full
external peer suite. Missing peer dependencies fail rather than skip. The peer
must be independently inspected and pinned by the consuming project; no peer
implementation is vendored here. The implementation was qualified against the
CardPress peer with SHA-256
`61147a11dc9c0ff0cb5458f84282410a1c45f488e5f90fc0019dee4cd339d53e`.

The external suite covers SCP02 i=55 and all four SCP03 S8/S16 random/pseudo
profiles, automatic and fixed host challenges, chained protected commands with
empty/case-2 and block-boundary payloads, maximum short APDU sizes, overflow
without state mutation, malformed response shapes, reserved/mismatched options,
tampered cryptograms and pseudo challenges, sequence-counter shape errors,
missing invoking AID, EXTERNAL AUTHENTICATE rejection, transport failure, and
`6700` without retry. Its result output contains counts and verdicts only.
`auth_probe` emits synthetic wire frames solely to the independent peer.

For an already built probe, the complete gate is:

```sh
python3 contrib/qualification/auth_peer.py \
  --peer /path/to/cardpress/core/tests/support/gp_card_peer.py \
  --probe /path/to/auth_probe --full
```

Without `--full`, the historical default still requires SCP02 and both S8
profiles; `--require-s16` also requires the two S16 authentication/registry cases.
Use `--full` to qualify a replacement of a backend that already supports S16.
