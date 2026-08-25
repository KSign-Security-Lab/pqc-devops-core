/* Nettle / Hogweed provider. SPDX-License-Identifier: Apache-2.0 */
#include <errno.h>
#include <string.h>
#include <sys/random.h>

#include <nettle/chacha-poly1305.h>
#include <nettle/ecc-curve.h>
#include <nettle/ecc.h>
#include <nettle/ecdsa.h>
#include <nettle/eddsa.h>
#include <nettle/gcm.h>
#include <nettle/hkdf.h>
#include <nettle/hmac.h>
#include <nettle/memops.h>
#include <nettle/sha2.h>
#include <nettle/sha3.h>

#include "internal/provider.h"

static int ntl_supports(sdc_alg alg)
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

/* Nettle has no system RNG; use the kernel CSPRNG. */
static sdc_status ntl_random(uint8_t *buf, size_t len)
{
    while (len) {
        ssize_t n = getrandom(buf, len, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return SDC_ERR_PROVIDER;
        }
        buf += n;
        len -= (size_t)n;
    }
    return SDC_OK;
}

/* nettle_random_func adapter (aborts nothing; getrandom on Linux does not
 * fail for blocking calls once the pool is initialised). */
static void ntl_rng(void *ctx, size_t len, uint8_t *dst)
{
    (void)ctx;
    if (ntl_random(dst, len) != SDC_OK)
        memset(dst, 0, len); /* unreachable in practice; caller checks keys */
}

const sdc_provider sdc_provider_nettle = {
    .name     = "nettle",
    .supports = ntl_supports,
    .random   = ntl_random,
};
