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

static sdc_status rc(OQS_STATUS s) { return s == OQS_SUCCESS ? SDC_OK : SDC_ERR_PROVIDER; }

/* -------------------------------------------------------------------- KEM */

static sdc_status oqs_kem_keypair(sdc_alg alg, uint8_t *pk, uint8_t *sk)
{
    OQS_KEM *k = OQS_KEM_new(kem_name(alg));
    if (!k)
        return SDC_ERR_PROVIDER;
    sdc_status st = rc(OQS_KEM_keypair(k, pk, sk));
    OQS_KEM_free(k);
    return st;
}

static sdc_status oqs_kem_encaps(sdc_alg alg, const uint8_t *pk,
                                 uint8_t *ct, uint8_t *ss)
{
    OQS_KEM *k = OQS_KEM_new(kem_name(alg));
    if (!k)
        return SDC_ERR_PROVIDER;
    sdc_status st = rc(OQS_KEM_encaps(k, ct, ss, pk));
    OQS_KEM_free(k);
    return st;
}

/* ML-KEM decapsulation uses implicit rejection: a tampered ciphertext yields
 * a pseudorandom shared secret rather than an error. */
static sdc_status oqs_kem_decaps(sdc_alg alg, const uint8_t *sk,
                                 const uint8_t *ct, uint8_t *ss)
{
    OQS_KEM *k = OQS_KEM_new(kem_name(alg));
    if (!k)
        return SDC_ERR_PROVIDER;
    sdc_status st = rc(OQS_KEM_decaps(k, ss, ct, sk));
    OQS_KEM_free(k);
    return st;
}

/* ------------------------------------------------------------- signatures */

static sdc_status oqs_sig_keypair(sdc_alg alg, uint8_t *pk, uint8_t *sk)
{
    OQS_SIG *s = OQS_SIG_new(sig_name(alg));
    if (!s)
        return SDC_ERR_PROVIDER;
    sdc_status st = rc(OQS_SIG_keypair(s, pk, sk));
    OQS_SIG_free(s);
    return st;
}

static sdc_status oqs_sign(sdc_alg alg, const uint8_t *sk,
                           const uint8_t *msg, size_t msg_len,
                           uint8_t *sig, size_t *sig_len)
{
    static const uint8_t empty[1];
    OQS_SIG *s = OQS_SIG_new(sig_name(alg));
    if (!s)
        return SDC_ERR_PROVIDER;
    sdc_status st = rc(OQS_SIG_sign(s, sig, sig_len, msg ? msg : empty, msg_len, sk));
    OQS_SIG_free(s);
    return st;
}

static sdc_status oqs_verify(sdc_alg alg, const uint8_t *pk,
                             const uint8_t *msg, size_t msg_len,
                             const uint8_t *sig, size_t sig_len)
{
    static const uint8_t empty[1];
    OQS_SIG *s = OQS_SIG_new(sig_name(alg));
    if (!s)
        return SDC_ERR_PROVIDER;
    OQS_STATUS r = OQS_SIG_verify(s, msg ? msg : empty, msg_len, sig, sig_len, pk);
    OQS_SIG_free(s);
    return r == OQS_SUCCESS ? SDC_OK : SDC_ERR_VERIFY_FAILED;
}

const sdc_provider sdc_provider_liboqs = {
    .name        = "liboqs",
    .init        = oqs_init,
    .cleanup     = oqs_cleanup,
    .supports    = oqs_supports,
    .random      = oqs_random,
    .kem_keypair = oqs_kem_keypair,
    .kem_encaps  = oqs_kem_encaps,
    .kem_decaps  = oqs_kem_decaps,
    .sig_keypair = oqs_sig_keypair,
    .sign        = oqs_sign,
    .verify      = oqs_verify,
};
