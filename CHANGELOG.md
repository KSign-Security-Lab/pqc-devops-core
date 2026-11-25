# Changelog

## 0.2.0

### Added
- Algorithms: AES-128-GCM, SHA-224, SHA3-384, BLAKE2b-512, HMAC-SHA256/512,
  PBKDF2-HMAC-SHA256, X25519 key agreement.
- Experimental hybrid KEM `X25519-ML-KEM-768`, composed in the core from
  whichever providers serve X25519, ML-KEM-768 and SHA3-256.
- New families and functions: `sdc_mac`/`sdc_mac_verify`, `sdc_pbkdf2`,
  `sdc_kex_keypair`/`sdc_kex_derive`, `sdc_sig_public_key`, incremental
  hashing (`sdc_hash_init/update/final/free`).
- Utilities: hex and base64 encoding, `sdc_ct_equal`, `sdc_family_name`,
  `sdc_alg_list`, `sdc_ctx_provider_count/name`.
- HKDF is derived from HMAC when no provider implements it (libgcrypt < 1.10).
- Example programs: `sdc_providers`, `sdc_hashsum`, `sdc_filecrypt`,
  `sdc_seal`, `sdc_signtool`, `sdc_kex_demo`, `sdc_bench`, with a CTest
  smoke test.
- Docs: API overview, provider guide, example file formats; CI workflow
  covering sanitizers and single-provider builds.

### Changed
- Providers are chosen per operation rather than per algorithm, so a
  provider can implement part of an algorithm and the next one fills in.
- PBKDF2 requires a non-empty salt on every provider.

### Fixed
- `sdc_ct_equal` no longer right-shifts a negative value.

New algorithm identifiers are appended, so existing `sdc_alg` values are
unchanged from 0.1.0.

## 0.1.0

- One C API (`sdc.h`) for AEAD, hashing, HKDF, signatures and KEMs over
  OpenSSL 3, Nettle, libgcrypt and liboqs, with a runtime provider registry,
  canonical key encodings, KAT and cross-provider tests.
