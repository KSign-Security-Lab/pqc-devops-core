<p align="right">🌐 <a href="./README.md">English</a> · <strong>한국어</strong></p>

![PQC DevOps 전환 Core](./assets/banner.ko.svg)

<p align="center">
  <a href="https://github.com/KSign-Security-Lab/pqc-devops-core/issues"><img alt="상태: 프로토타입 개발 예정" src="https://img.shields.io/badge/status-prototypes%20planned-10b7a0?style=flat-square"></a>
  <a href="https://github.com/KSign-Security-Lab/pqc-devops-guide"><img alt="연관 저장소: Guide" src="https://img.shields.io/badge/companion-Guide-9b7ff9?style=flat-square"></a>
  <a href="./LICENSE"><img alt="라이선스: Apache 2.0" src="https://img.shields.io/badge/license-Apache--2.0-64748b?style=flat-square"></a>
</p>

**DevOps 기반 양자내성암호(PQC) 전환을 위한 핵심 구현 저장소입니다.** Crypto-Agility SDK, 레거시-SDC API 전환 템플릿, C/Java 스니핏, PIU 지식베이스를 개발하는 것을 목표로 합니다.

> **프로젝트 단계:** 초기 구현 작업을 Issue로 관리하고 있습니다. **Crypto-Agility SDK의 첫 C 프로토타입**이 포함되어 있습니다([아래](#crypto-agility-sdk-c--프로토타입) 참고). 나머지 컴포넌트는 계획 단계이며 배포된 패키지는 아직 없습니다.

<p align="center">
  <a href="#목표-아키텍처">아키텍처</a> ·
  <a href="#개발-대상-컴포넌트">컴포넌트</a> ·
  <a href="#구현-원칙">구현 원칙</a> ·
  <a href="https://github.com/KSign-Security-Lab/pqc-devops-core/issues">로드맵 ↗</a>
</p>

## 개발 목적

PQC 전환 과정에서 애플리케이션이 특정 암호 라이브러리에 직접 종속되는 문제를 줄이는 것이 목표입니다. 비즈니스 로직에 암호 구현체를 고정하는 대신, 공통 API와 재사용 가능한 전환 컴포넌트를 제공하는 구조를 지향합니다.

**[Guide 저장소](https://github.com/KSign-Security-Lab/pqc-devops-guide)**는 공정·API·CI 구조·검증 기준을 정의하고, **Core**는 그 명세를 기반으로 필요한 기능을 구현합니다.

## 목표 아키텍처

![레거시 암호 호출에서 전환 규칙, SDC API, 암호 구현체로 이어지는 목표 컴포넌트 구조와 PIU 데이터 및 스니핏](./assets/architecture.ko.svg)

*구현 목표를 설명하는 개념도입니다. 위 컴포넌트가 모두 구현되었다는 의미는 아닙니다.*

### 전환 흐름

1. **탐지·매핑:** YAML/JSON 전환 규칙으로 레거시 암호 API 호출을 탐지하고 SDC-API 호출로 매핑합니다.
2. **표준 API 계층:** 애플리케이션 코드와 실제 암호 구현체 사이에 알고리즘 중립 인터페이스를 정의합니다.
3. **동적 구현체 연동:** Crypto-Agility SDK를 통해 암호 라이브러리를 선택·연결할 수 있는 구조를 설계합니다.
4. **자원 제약 평가:** PIU 프로파일, 구현 메타데이터, C/Java 스니핏을 활용해 자원 요구사항을 점검합니다.

## 개발 대상 컴포넌트

| 컴포넌트 | 개발 범위 | Issue |
|:--|:--|:--|
| **전환 템플릿** | 레거시 암호 API 탐지 및 표준 SDC-API 매핑을 위한 YAML/JSON 규칙 | [#3](https://github.com/KSign-Security-Lab/pqc-devops-core/issues/3) |
| **PQC 스니핏 라이브러리** | C/Java 재사용 코드, 최악 조건 자원 예약(WCRR), 하드웨어별 자원 할당 전략 | [#4](https://github.com/KSign-Security-Lab/pqc-devops-core/issues/4) |
| **Crypto-Agility SDK** | 알고리즘 중립 API 접근, 동적 라이브러리 바인딩, 자원 가용성 검사 | [#5](https://github.com/KSign-Security-Lab/pqc-devops-core/issues/5) |
| **PIU 지식베이스** | PIU 메타데이터, 알고리즘, 하드웨어 프로파일, 임계치, 검증 데이터의 SSOT | [#7](https://github.com/KSign-Security-Lab/pqc-devops-core/issues/7) |

위 항목은 **개발 예정 산출물**입니다. 세부 범위와 완료 조건은 각 Issue를 기준으로 관리합니다.

## Crypto-Agility SDK (C) — 프로토타입

`libsdc`는 AEAD, 해시, HKDF, 전자서명, KEM을 위한 **단일 C API**(`include/sdc/sdc.h`)를 제공합니다. 애플리케이션은 *알고리즘*만 지정하고, 실제 연산을 수행할 라이브러리는 Provider 레지스트리가 선택합니다.

| 알고리즘 | OpenSSL 3 | Nettle | libgcrypt | liboqs |
|:--|:-:|:-:|:-:|:-:|
| AES-256-GCM, ChaCha20-Poly1305 | ✓ | ✓ | ✓ | |
| SHA-256/384/512, SHA3-256/512 | ✓ | ✓ | ✓ | |
| HKDF-SHA256/512 | ✓ | ✓ | | |
| Ed25519, ECDSA-P256-SHA256 | ✓ | ✓ | ✓ | |
| ML-KEM-512/768/1024, ML-DSA-44/65/87 | | | | ✓ |

**빌드 및 테스트** (CMake 3.16 이상, OpenSSL 3.0 이상, Nettle/Hogweed + GMP, libgcrypt 개발 패키지 필요. liboqs는 설치되어 있지 않으면 자동으로 내려받습니다):

```bash
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

`-DSDC_WITH_OPENSSL|NETTLE|GCRYPT|LIBOQS=OFF`로 백엔드를 끌 수 있고, `-DSDC_SANITIZE=ON`으로 Sanitizer 빌드를 할 수 있습니다.

**사용 예**

```c
#include <sdc/sdc.h>

sdc_ctx *ctx;
sdc_ctx_new(&ctx, NULL);               /* 기본 순서, 또는 "nettle,openssl" */

uint8_t out[sizeof msg + 16];
size_t out_len = sizeof out;
sdc_status st = sdc_aead_encrypt(ctx, SDC_ALG_AES_256_GCM, key, 32, nonce, 12,
                                 aad, aad_len, msg, sizeof msg, out, &out_len);
printf("served by %s\n", sdc_ctx_provider_for(ctx, SDC_ALG_AES_256_GCM));
sdc_ctx_free(ctx);
```

재컴파일 없이 백엔드 전환: `SDC_PROVIDER=gcrypt ./build/examples/sdc_demo`. 키와 서명은 Provider와 무관한 표준 인코딩(`sdc.h`에 명시)을 사용하므로 한 Provider로 생성한 키를 다른 Provider에서도 쓸 수 있으며, 교차 Provider 테스트(`tests/test_interop.c`)가 이를 검증합니다.

## 구현 원칙

| 원칙 | 설계 방향 |
|:--|:--|
| **알고리즘 중립성** | 애플리케이션에 노출되는 인터페이스와 암호 구현체의 선택을 분리합니다. |
| **통제 가능한 전환** | API 탐지·매핑 규칙을 검토할 수 있는 YAML/JSON 파일로 표현합니다. |
| **자원 가용성** | SDK 과제에서 제시된 `A + B ≤ C` 안전 조건을 검토합니다. 각 변수의 정의와 적용 방식은 추후 명세에서 확정합니다. |
| **하드웨어별 재사용성** | C/Java 스니핏과 PIU 프로파일 정보를 자원 할당·검증 과정에 연결합니다. |
| **추적성** | 구현 변경사항을 [Guide 명세](https://github.com/KSign-Security-Lab/pqc-devops-guide/issues) 및 검증 증적과 연결합니다. |

## 개발 참여

**저장소 확인하기**

```bash
git clone https://github.com/KSign-Security-Lab/pqc-devops-core.git
cd pqc-devops-core
```

SDK 프로토타입 빌드 방법은 [Crypto-Agility SDK (C)](#crypto-agility-sdk-c--프로토타입)를 참고하세요. 그 외 작업은 **[구현 Issue](https://github.com/KSign-Security-Lab/pqc-devops-core/issues)**를 기준으로 진행합니다.

**작업 흐름**

1. 관련 [Guide 설계 Issue](https://github.com/KSign-Security-Lab/pqc-devops-guide/issues)와 요구사항을 확인합니다.
2. [Core 구현 Issue](https://github.com/KSign-Security-Lab/pqc-devops-core/issues)를 선택하고 API 및 데이터 경계를 명확히 합니다.
3. 컴포넌트 구현 단계에서 테스트와 자원 측정 결과를 추가합니다.
4. 요구사항과 검증 증적을 연결한 Pull Request로 변경사항을 제출합니다.

## 연관 자료

- **[PQC DevOps Guide](https://github.com/KSign-Security-Lab/pqc-devops-guide)** — 설계 명세, 아키텍처, CI 연동, 거버넌스.
- **[NIST PQC 프로젝트](https://csrc.nist.gov/projects/post-quantum-cryptography/)** — 외부 표준 참고 자료이며, 구현의 표준 준수·인증을 의미하지 않습니다.

---

<sub>**KSign Security Lab** · <a href="./LICENSE">Apache License 2.0</a></sub>

