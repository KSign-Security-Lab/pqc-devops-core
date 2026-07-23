/* Algorithm metadata. SPDX-License-Identifier: Apache-2.0 */
#include <ctype.h>
#include <string.h>

#include "internal/provider.h"

/*                 alg                          name                 family            key non tag dig   pk    sk   sig   ct  ss */
#define A(alg, name, fam, k, n, t, d, pk, sk, sig, ct, ss) \
    [alg] = { alg, name, fam, k, n, t, d, pk, sk, sig, ct, ss }

static const sdc_alg_info g_algs[SDC_ALG__COUNT] = {
    A(SDC_ALG_AES_256_GCM,       "AES-256-GCM",       SDC_FAMILY_AEAD, 32, 12, 16,  0,    0,    0,    0,    0,  0),
    A(SDC_ALG_CHACHA20_POLY1305, "ChaCha20-Poly1305", SDC_FAMILY_AEAD, 32, 12, 16,  0,    0,    0,    0,    0,  0),
    A(SDC_ALG_SHA256,            "SHA-256",           SDC_FAMILY_HASH,  0,  0,  0, 32,    0,    0,    0,    0,  0),
    A(SDC_ALG_SHA384,            "SHA-384",           SDC_FAMILY_HASH,  0,  0,  0, 48,    0,    0,    0,    0,  0),
    A(SDC_ALG_SHA512,            "SHA-512",           SDC_FAMILY_HASH,  0,  0,  0, 64,    0,    0,    0,    0,  0),
    A(SDC_ALG_SHA3_256,          "SHA3-256",          SDC_FAMILY_HASH,  0,  0,  0, 32,    0,    0,    0,    0,  0),
    A(SDC_ALG_SHA3_512,          "SHA3-512",          SDC_FAMILY_HASH,  0,  0,  0, 64,    0,    0,    0,    0,  0),
};
#undef A
