<p align="right">🌐 <strong>English</strong> · <a href="./README.ko.md">한국어</a></p>

![PQC DevOps Transition Core](./assets/banner.en.svg)

<p align="center">
  <a href="https://github.com/KSign-Security-Lab/pqc-devops-core/issues"><img alt="Status: prototype planning" src="https://img.shields.io/badge/status-prototypes%20planned-10b7a0?style=flat-square"></a>
  <a href="https://github.com/KSign-Security-Lab/pqc-devops-guide"><img alt="Companion repository: Guide" src="https://img.shields.io/badge/companion-Guide-9b7ff9?style=flat-square"></a>
  <a href="./LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache--2.0-64748b?style=flat-square"></a>
</p>

**The planned implementation layer for DevOps-driven post-quantum cryptography (PQC) transition.** It brings together a Crypto-Agility SDK, legacy-to-SDC API mapping templates, reusable C/Java snippets, and a PIU knowledge base.

> **Project stage:** Initial implementation work is tracked in issues. A first **C prototype of the Crypto-Agility SDK** is available (see [below](#crypto-agility-sdk-c--prototype)); other components are still planned and there are no published packages yet.

<p align="center">
  <a href="#target-architecture">Architecture</a> ·
  <a href="#planned-components">Components</a> ·
  <a href="#implementation-principles">Principles</a> ·
  <a href="https://github.com/KSign-Security-Lab/pqc-devops-core/issues">Roadmap ↗</a>
</p>

## What this repository builds

The goal is to reduce application-level coupling to specific cryptographic libraries during PQC migration. Rather than embedding a particular provider across business logic, the target system defines a standardized integration surface and reusable transition components.

The **[Guide repository](https://github.com/KSign-Security-Lab/pqc-devops-guide)** owns the process definitions, interface specifications, CI architecture, and verification criteria. **Core** turns selected specifications into implementations.

## Target architecture

![Planned data flow from legacy crypto calls to mapping rules, SDC API and cryptographic providers, supported by PIU data and snippets](./assets/architecture.en.svg)

*Target component flow. The diagram describes intended responsibilities; it does not assert that these modules already exist.*

### Transition path

1. **Detect and map** legacy cryptographic API calls using versioned YAML/JSON transition rules.
2. **Use a standardized API boundary** to separate application code from specific cryptographic implementations.
3. **Bind cryptographic providers** through the proposed Crypto-Agility SDK without hardwiring an algorithm to business logic.
4. **Evaluate resource constraints** using PIU profiles, implementation metadata, and reusable C/Java snippets.

## Planned components

| Component | Responsibilities | Issue |
|:--|:--|:--|
| **Transition Templates** | YAML/JSON rules for detecting legacy calls and mapping them to standardized SDC APIs | [#3](https://github.com/KSign-Security-Lab/pqc-devops-core/issues/3) |
| **PQC Snippet Library** | Reusable C/Java examples, Worst Condition Resource Reservation (WCRR), hardware-aware allocation strategies | [#4](https://github.com/KSign-Security-Lab/pqc-devops-core/issues/4) |
| **Crypto-Agility SDK** | Algorithm-neutral access, dynamic library binding, and resource-availability checks | [#5](https://github.com/KSign-Security-Lab/pqc-devops-core/issues/5) |
| **PIU Knowledge Base** | Single Source of Truth (SSOT) for PIU metadata, algorithms, hardware profiles, thresholds, and verification data | [#7](https://github.com/KSign-Security-Lab/pqc-devops-core/issues/7) |

These are **planned deliverables**. Individual issues remain the source of truth for the precise scope and acceptance criteria.

## Crypto-Agility SDK (C) — prototype

`libsdc` exposes **one C API** (`include/sdc/sdc.h`) for AEAD, hashing, HKDF, signatures and KEMs. Application code names an *algorithm*; a provider registry decides which library performs it.

| Algorithm | OpenSSL 3 | Nettle | libgcrypt | liboqs |
|:--|:-:|:-:|:-:|:-:|
| AES-128/256-GCM, ChaCha20-Poly1305 | ✓ | ✓ | ✓ | |
| SHA-224/256/384/512, SHA3-256/384/512 | ✓ | ✓ | ✓ | |
| BLAKE2b-512 | ✓ | | ✓ | |
| HMAC-SHA256/512, PBKDF2-HMAC-SHA256 | ✓ | ✓ | ✓ | |
| HKDF-SHA256/512 | ✓ | ✓ | via HMAC¹ | |
| Ed25519, ECDSA-P256-SHA256, X25519 | ✓ | ✓ | ✓ | |
| ML-KEM-512/768/1024, ML-DSA-44/65/87 | | | | ✓ |

¹ Composed by the SDK core from algorithms the providers do offer; `sdc_ctx_provider_for()` reports `"core"`. The experimental hybrid KEM **X25519-ML-KEM-768** is built the same way from X25519 and ML-KEM-768, so it works with any provider combination that has both.

**Build and test** (needs CMake ≥ 3.16, OpenSSL ≥ 3.0, Nettle/Hogweed + GMP, libgcrypt dev packages; liboqs is fetched automatically unless installed):

```bash
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Disable a backend with `-DSDC_WITH_OPENSSL|NETTLE|GCRYPT|LIBOQS=OFF`; build with sanitizers via `-DSDC_SANITIZE=ON`.

**Use**

```c
#include <sdc/sdc.h>

sdc_ctx *ctx;
sdc_ctx_new(&ctx, NULL);               /* default order, or "nettle,openssl" */

uint8_t out[sizeof msg + 16];
size_t out_len = sizeof out;
sdc_status st = sdc_aead_encrypt(ctx, SDC_ALG_AES_256_GCM, key, 32, nonce, 12,
                                 aad, aad_len, msg, sizeof msg, out, &out_len);
printf("served by %s\n", sdc_ctx_provider_for(ctx, SDC_ALG_AES_256_GCM));
sdc_ctx_free(ctx);
```

More: [API overview](./docs/API.md) · [Adding a provider](./docs/ADDING_A_PROVIDER.md) · [Example programs](./examples/README.md) (file encryption, sealing to a public key, signing, key exchange, benchmarks).

Switch the backend without recompiling: `SDC_PROVIDER=gcrypt ./build/examples/sdc_demo`. Keys and signatures use canonical encodings (documented in `sdc.h`), so a key generated by one provider works with another — the cross-provider test (`tests/test_interop.c`) checks this.

## Implementation principles

| Principle | Planned design direction |
|:--|:--|
| **Algorithm neutrality** | Keep application-facing interfaces distinct from crypto-provider selection. |
| **Controlled migration** | Express call-detection and mapping decisions as reviewable YAML/JSON rules. |
| **Resource awareness** | Evaluate the `A + B ≤ C` safety condition proposed for the SDK; variable definitions and enforcement behavior remain to be specified. |
| **Hardware-aware reuse** | Connect C/Java snippets and PIU profiling data to resource allocation and verification decisions. |
| **Traceability** | Tie implementation changes to [Guide specifications](https://github.com/KSign-Security-Lab/pqc-devops-guide/issues) and issue-level verification evidence. |

## Get involved

**Browse the scaffold**

```bash
git clone https://github.com/KSign-Security-Lab/pqc-devops-core.git
cd pqc-devops-core
```

To build the SDK prototype, see [Crypto-Agility SDK (C)](#crypto-agility-sdk-c--prototype). Other work starts from the **[implementation issue tracker](https://github.com/KSign-Security-Lab/pqc-devops-core/issues)**.

**Development loop**

1. Read the related [Guide specification issue](https://github.com/KSign-Security-Lab/pqc-devops-guide/issues).
2. Select a [Core implementation issue](https://github.com/KSign-Security-Lab/pqc-devops-core/issues) and describe the proposed API/data boundary.
3. Add implementation, tests, and resource measurements as the component becomes available.
4. Open a pull request linking the requirement and the corresponding verification evidence.

## Related resources

- **[PQC DevOps Guide](https://github.com/KSign-Security-Lab/pqc-devops-guide)** — specifications, architecture, CI integration, and governance.
- **[NIST PQC project](https://csrc.nist.gov/projects/post-quantum-cryptography/)** — external standards context, **not** an implementation conformance claim.

---

<sub>Maintained by **KSign Security Lab** · Licensed under <a href="./LICENSE">Apache License 2.0</a>.</sub>

