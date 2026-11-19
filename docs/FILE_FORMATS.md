# Example file formats

These formats exist to demonstrate the SDK. They are versioned so they can
change, but they have not had a protocol review.

## `sdc_filecrypt` (password)

| Offset | Size | Field |
|--:|--:|:--|
| 0 | 4 | magic `SDCF` |
| 4 | 1 | version (1) |
| 5 | 1 | AEAD algorithm id (`sdc_alg` value) |
| 6 | 4 | PBKDF2 iterations, big-endian (1 … 10,000,000) |
| 10 | 16 | random salt |
| 26 | 12 | random nonce |
| 38 | n + 16 | ciphertext ‖ tag |

* Key: `PBKDF2-HMAC-SHA256(password, salt, iterations)`, sized for the AEAD.
* The 38-byte header is the AEAD associated data, so changing any field
  (algorithm, iterations, salt) makes decryption fail.

## `sdc_seal` (public key)

Key files: `alg id (1 byte) ‖ raw public or secret key`.

| Offset | Size | Field |
|--:|--:|:--|
| 0 | 4 | magic `SDCS` |
| 4 | 1 | version (1) |
| 5 | 1 | KEM algorithm id |
| 6 | ct_len | KEM ciphertext |
| 6 + ct_len | n + 16 | AES-256-GCM ciphertext ‖ tag |

* `key = HKDF-SHA256(ikm = shared secret, salt = empty, info = "sdc_seal v1")`.
* Each seal uses a fresh encapsulation, so the key is single-use and the
  nonce is fixed at zero.
* Associated data is the header plus KEM ciphertext.

## `sdc_signtool`

Key and signature files: `alg id (1 byte) ‖ raw bytes`. Signatures are
detached and cover the file contents exactly.

## Hybrid KEM `X25519-ML-KEM-768`

```
pk = pk_ML-KEM (1184) ‖ pk_X25519 (32)
sk = sk_ML-KEM (2400) ‖ sk_X25519 (32) ‖ pk_X25519 (32)
ct = ct_ML-KEM (1088) ‖ ephemeral pk_X25519 (32)
ss = SHA3-256(ss_ML-KEM ‖ ss_X25519 ‖ ct_X25519 ‖ pk_X25519 ‖ "SDC-X25519-MLKEM768-v1")
```

The combiner follows X-Wing's structure but is **not** X-Wing: key formats
and the label differ.
