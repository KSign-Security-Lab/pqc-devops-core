/* liboqs provider: ML-KEM (FIPS 203) and ML-DSA (FIPS 204).
 * SPDX-License-Identifier: Apache-2.0 */
#include <oqs/oqs.h>

#include "internal/provider.h"

static const char *kem_name(sdc_alg alg)
{
    switch (alg) {
    case SDC_ALG_ML_KEM_512:  return OQS_KEM_alg_ml_kem_512;
    case SDC_ALG_ML_KEM_768:  return OQS_KEM_alg_ml_kem_768;
    case SDC_ALG_ML_KEM_1024: return OQS_KEM_alg_ml_kem_1024;
    default:                  return NULL;
    }
}

static const char *sig_name(sdc_alg alg)
{
    switch (alg) {
    case SDC_ALG_ML_DSA_44: return OQS_SIG_alg_ml_dsa_44;
    case SDC_ALG_ML_DSA_65: return OQS_SIG_alg_ml_dsa_65;
    case SDC_ALG_ML_DSA_87: return OQS_SIG_alg_ml_dsa_87;
    default:                return NULL;
    }
}

static sdc_status oqs_init(void)
{
    OQS_init();
    return SDC_OK;
}

static void oqs_cleanup(void) { OQS_destroy(); }

static int oqs_supports(sdc_alg alg)
{
    const char *n = kem_name(alg);
    if (n)
        return OQS_KEM_alg_is_enabled(n);
    n = sig_name(alg);
    return n ? OQS_SIG_alg_is_enabled(n) : 0;
}

static sdc_status oqs_random(uint8_t *buf, size_t len)
{
    OQS_randombytes(buf, len);
    return SDC_OK;
}

const sdc_provider sdc_provider_liboqs = {
    .name     = "liboqs",
    .init     = oqs_init,
    .cleanup  = oqs_cleanup,
    .supports = oqs_supports,
    .random   = oqs_random,
};
