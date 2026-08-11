/* OpenSSL 3 provider. SPDX-License-Identifier: Apache-2.0 */
#include <limits.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>

#include "internal/provider.h"

static int ossl_supports(sdc_alg alg)
{
    switch (alg) {
    case SDC_ALG_AES_256_GCM:
    case SDC_ALG_CHACHA20_POLY1305:
    case SDC_ALG_SHA256:
    case SDC_ALG_SHA384:
    case SDC_ALG_SHA512:
    case SDC_ALG_SHA3_256:
    case SDC_ALG_SHA3_512:
    case SDC_ALG_HKDF_SHA256:
    case SDC_ALG_HKDF_SHA512:
    case SDC_ALG_ED25519:
    case SDC_ALG_ECDSA_P256_SHA256:
        return 1;
    default:
        return 0;
    }
}

static sdc_status ossl_random(uint8_t *buf, size_t len)
{
    while (len) {
        int n = len > INT_MAX ? INT_MAX : (int)len;
        if (RAND_bytes(buf, n) != 1)
            return SDC_ERR_PROVIDER;
        buf += n;
        len -= (size_t)n;
    }
    return SDC_OK;
}

const sdc_provider sdc_provider_openssl = {
    .name     = "openssl",
    .supports = ossl_supports,
    .random   = ossl_random,
};
