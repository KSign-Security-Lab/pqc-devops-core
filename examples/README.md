# SDC examples

Every program here names algorithms only, never a crypto library. Pick the
backend at run time with `SDC_PROVIDER` (a single provider or an ordered
list such as `liboqs,nettle`).

| Program | What it shows |
|:--|:--|
| `sdc_demo` | ML-KEM → HKDF → AES-GCM, then ML-DSA / Ed25519 signing |
| `sdc_providers` | Which provider serves each algorithm in the current configuration |
| `sdc_hashsum` | `sha256sum`-style hashing with the incremental hash API |
| `sdc_filecrypt` | Password-based file encryption (PBKDF2 + AEAD) |
| `sdc_seal` | Encrypt a file to a public key (hybrid X25519 + ML-KEM-768 by default) |
| `sdc_signtool` | Detached file signatures (ML-DSA-65 by default) |
| `sdc_kex_demo` | Two parties on different libraries agreeing on a session key |
| `sdc_bench` | Throughput and operations per second, per provider |

## Quick tour

```bash
B=build/examples

$B/sdc_providers                                   # capability matrix
$B/sdc_hashsum -a sha3-256 README.md

$B/sdc_filecrypt enc -a chacha20-poly1305 "pass phrase" notes.txt notes.sdcf
SDC_PROVIDER=nettle $B/sdc_filecrypt dec "pass phrase" notes.sdcf -

$B/sdc_seal keygen alice.pk alice.sk
$B/sdc_seal seal alice.pk report.pdf report.sealed
$B/sdc_seal open alice.sk report.sealed report.pdf

$B/sdc_signtool keygen -a ml-dsa-87 me.pk me.sk
$B/sdc_signtool sign me.sk release.tar release.sig
$B/sdc_signtool verify me.pk release.tar release.sig   # exit 2 if invalid

$B/sdc_kex_demo openssl,liboqs gcrypt,liboqs           # Alice vs Bob
$B/sdc_bench 0.5
```

File formats for `sdc_filecrypt` and `sdc_seal` are described in
[docs/FILE_FORMATS.md](../docs/FILE_FORMATS.md). These are demonstration
formats, not a stable or reviewed protocol.

`sdc_filecrypt` takes the password as an argument for brevity; that exposes
it in the process list, so do not use it this way on shared machines.
