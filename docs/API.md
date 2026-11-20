# SDC C API overview

The whole API is in [`include/sdc/sdc.h`](../include/sdc/sdc.h); this page
explains how the pieces fit together.

## Concepts

* **Algorithm (`sdc_alg`)** — what the application asks for, e.g.
  `SDC_ALG_AES_256_GCM`. Each belongs to one **family**.
* **Provider** — a backend library (`openssl`, `nettle`, `gcrypt`,
  `liboqs`) compiled into `libsdc`.
* **Context (`sdc_ctx`)** — an ordered list of providers. `NULL` means the
  default order, overridable with `SDC_PROVIDER`.

## Families and functions

| Family | Algorithms | Functions |
|:--|:--|:--|
| AEAD | AES-128/256-GCM, ChaCha20-Poly1305 | `sdc_aead_encrypt`, `sdc_aead_decrypt` |
| HASH | SHA-224/256/384/512, SHA3-256/384/512, BLAKE2b-512 | `sdc_hash`, `sdc_hash_init/update/final/free` |
| MAC | HMAC-SHA256/512 | `sdc_mac`, `sdc_mac_verify` |
| KDF | HKDF-SHA256/512 | `sdc_hkdf` |
| PBKDF | PBKDF2-HMAC-SHA256 | `sdc_pbkdf2` |
| SIG | Ed25519, ECDSA-P256-SHA256, ML-DSA-44/65/87 | `sdc_sig_keypair`, `sdc_sig_public_key`, `sdc_sign`, `sdc_verify` |
| KEM | ML-KEM-512/768/1024, X25519-ML-KEM-768 | `sdc_kem_keypair`, `sdc_kem_encaps`, `sdc_kem_decaps` |
| KEX | X25519 | `sdc_kex_keypair`, `sdc_kex_derive` |

Utilities: `sdc_random`, `sdc_memzero`, `sdc_ct_equal`, hex and base64
helpers, `sdc_alg_list`, `sdc_alg_get_info`.

## How a provider is chosen

For each call the SDK walks the context's provider list and uses the first
provider that **supports the algorithm and implements that operation**. A
provider can therefore cover part of an algorithm (libgcrypt signs Ed25519
but cannot derive a public key) and the next provider fills the gap.

Some algorithms are **composed by the core** from others; for these
`sdc_ctx_provider_for` returns `"core"`:

* `X25519-ML-KEM-768` — X25519 + ML-KEM-768 + SHA3-256, each from whichever
  provider serves it.
* HKDF when no provider has it natively — built from HMAC (RFC 5869).

## Buffers and errors

* Output buffers take an in/out length. Too small → `SDC_ERR_BUFFER_TOO_SMALL`
  and the required size is written back. `sdc_alg_get_info` gives every
  fixed size up front.
* `SDC_ERR_AUTH_FAILED` (AEAD) and `SDC_ERR_VERIFY_FAILED` (signatures, MAC)
  are the only "the data is bad" results; on AEAD failure the plaintext
  buffer is zeroed.
* `SDC_ERR_NO_PROVIDER` means nothing in the context can do the operation.

## Encodings

Keys and signatures have one provider-independent encoding, so material
created by one backend works with another:

| Algorithm | Public key | Secret key | Signature |
|:--|:--|:--|:--|
| Ed25519 | 32-byte point | 32-byte seed | 64 bytes |
| ECDSA-P256 | 65-byte uncompressed point | 32-byte scalar | r ‖ s, 64 bytes |
| X25519 | 32 bytes | 32 bytes | – |
| ML-KEM / ML-DSA | FIPS 203 / 204 | FIPS 203 / 204 | FIPS 204 |

## Thread safety

`sdc_init` is idempotent and thread-safe. Contexts are read-only after
creation and can be shared between threads; an `sdc_hash_ctx` cannot.
Call `sdc_cleanup` once, after all other SDK use has finished.
