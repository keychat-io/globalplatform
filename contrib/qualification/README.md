# Independent SCP compatibility probe

This host-only probe calls the real SDK authentication and protected GET STATUS
APIs against an external independent Python/pyca card peer. All keys are
synthetic. It does not use a physical card or claim hardware qualification.

Build `auth_probe.c` against the SDK and a host OpenSSL installation. The static callback profile uses normal SDK context establishment. A desktop
profile probe explicitly initializes the host OpenSSL default/legacy providers.
Supply the CardPress `core/tests/support/gp_card_peer.py` peer as an explicit path:

```
python3 auth_peer.py --peer /path/to/cardpress/core/tests/support/gp_card_peer.py --probe /path/to/auth_probe
```

Default success requires SCP02 i=55 and SCP03 S8 random and pseudo-random modes.
Both S16 modes are also exercised and their actual challenge lengths and failures
are reported. Use `--require-s16` for the full compatibility gate; the pinned
upstream implementation currently fails this gate because INITIALIZE UPDATE uses
an eight-byte host challenge. A passing default probe does not qualify a complete
replacement of a backend that already supports S16.

The peer must be independently inspected and pinned by the consuming project.
No peer code is vendored here. No application credentials should be supplied to
this probe. It deliberately does not implement authentication retry or downgrade.
