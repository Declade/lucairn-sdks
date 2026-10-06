# Pinned trust roots for lucairn-bundle-verify

Embedded into the binary at build time; nothing is fetched at verify time.

| File | What | Source | SHA-256 of file |
|---|---|---|---|
| `freetsa.pem` | FreeTSA root CA (RFC 3161 timestamps) | https://freetsa.org/files/cacert.pem — identical to the witness pin in dual-sandbox-architecture `services/veil-witness/internal/verifier/trustroots/freetsa.pem` | `2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438` |
| `rekor-public-good.pem` | Sigstore public-good Rekor log key, log ID `c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d` | Sigstore TUF `trusted_root.json`, `tlogs[0]` (`https://rekor.sigstore.dev`, valid from 2021-01-12) | `dce5ef715502ec9f3cdfd11f8cc384b31a6141023d3e7595e9908a81cb6241bd` |

`anchor_test.go` recomputes both pins. A swap must update the test in the same commit.
