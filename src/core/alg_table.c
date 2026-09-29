/* Algorithm metadata. SPDX-License-Identifier: Apache-2.0 */
#include <ctype.h>
#include <string.h>

#include "internal/provider.h"

/* Columns: key, nonce, tag, digest, pk, sk, sig (max), kem ct, shared secret (bytes). */
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
    A(SDC_ALG_HKDF_SHA256,       "HKDF-SHA256",       SDC_FAMILY_KDF,   0,  0,  0, 32,    0,    0,    0,    0,  0),
    A(SDC_ALG_HKDF_SHA512,       "HKDF-SHA512",       SDC_FAMILY_KDF,   0,  0,  0, 64,    0,    0,    0,    0,  0),
    A(SDC_ALG_ED25519,           "Ed25519",           SDC_FAMILY_SIG,   0,  0,  0,  0,   32,   32,   64,    0,  0),
    A(SDC_ALG_ECDSA_P256_SHA256, "ECDSA-P256-SHA256", SDC_FAMILY_SIG,   0,  0,  0, 32,   65,   32,   64,    0,  0),
    A(SDC_ALG_ML_DSA_44,         "ML-DSA-44",         SDC_FAMILY_SIG,   0,  0,  0,  0, 1312, 2560, 2420,    0,  0),
    A(SDC_ALG_ML_DSA_65,         "ML-DSA-65",         SDC_FAMILY_SIG,   0,  0,  0,  0, 1952, 4032, 3309,    0,  0),
    A(SDC_ALG_ML_DSA_87,         "ML-DSA-87",         SDC_FAMILY_SIG,   0,  0,  0,  0, 2592, 4896, 4627,    0,  0),
    A(SDC_ALG_ML_KEM_512,        "ML-KEM-512",        SDC_FAMILY_KEM,   0,  0,  0,  0,  800, 1632,    0,  768, 32),
    A(SDC_ALG_ML_KEM_768,        "ML-KEM-768",        SDC_FAMILY_KEM,   0,  0,  0,  0, 1184, 2400,    0, 1088, 32),
    A(SDC_ALG_ML_KEM_1024,       "ML-KEM-1024",       SDC_FAMILY_KEM,   0,  0,  0,  0, 1568, 3168,    0, 1568, 32),
    A(SDC_ALG_AES_128_GCM,       "AES-128-GCM",       SDC_FAMILY_AEAD, 16, 12, 16,  0,    0,    0,    0,    0,  0),
};
#undef A

const sdc_alg_info *sdc__alg_info(sdc_alg alg)
{
    if ((int)alg <= SDC_ALG_NONE || alg >= SDC_ALG__COUNT)
        return NULL;
    return &g_algs[alg];
}

sdc_status sdc_alg_get_info(sdc_alg alg, sdc_alg_info *info)
{
    const sdc_alg_info *ai = sdc__alg_info(alg);
    if (!ai)
        return SDC_ERR_UNSUPPORTED;
    if (!info)
        return SDC_ERR_INVALID_ARG;
    *info = *ai;
    return SDC_OK;
}

const char *sdc_alg_name(sdc_alg alg)
{
    const sdc_alg_info *ai = sdc__alg_info(alg);
    return ai ? ai->name : NULL;
}

static int ieq(const char *a, const char *b)
{
    for (; *a && *b; a++, b++)
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return 0;
    return *a == *b;
}

sdc_alg sdc_alg_from_name(const char *name)
{
    if (!name)
        return SDC_ALG_NONE;
    for (int i = SDC_ALG_NONE + 1; i < SDC_ALG__COUNT; i++)
        if (ieq(name, g_algs[i].name))
            return (sdc_alg)i;
    return SDC_ALG_NONE;
}

const char *sdc_family_name(sdc_family family)
{
    switch (family) {
    case SDC_FAMILY_AEAD: return "AEAD";
    case SDC_FAMILY_HASH: return "HASH";
    case SDC_FAMILY_KDF:  return "KDF";
    case SDC_FAMILY_SIG:  return "SIG";
    case SDC_FAMILY_KEM:  return "KEM";
    default:              return NULL;
    }
}

size_t sdc_alg_list(sdc_family family, sdc_alg *out, size_t cap)
{
    size_t n = 0;
    for (int i = SDC_ALG_NONE + 1; i < SDC_ALG__COUNT; i++) {
        if (family != SDC_FAMILY_NONE && g_algs[i].family != family)
            continue;
        if (out && n < cap)
            out[n] = (sdc_alg)i;
        n++;
    }
    return n;
}
