/* libgcrypt provider. SPDX-License-Identifier: Apache-2.0
 *
 * HKDF is not offered: libgcrypt < 1.10 has no HKDF, and the registry falls
 * back to another provider for it.
 */
#include <string.h>

#include <gcrypt.h>

#include "internal/provider.h"

#define SDC_GCRYPT_MIN_VERSION "1.8.0"

static sdc_status gc_init(void)
{
    if (gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
        return SDC_OK; /* the application already initialised libgcrypt */
    if (!gcry_check_version(SDC_GCRYPT_MIN_VERSION))
        return SDC_ERR_PROVIDER;
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    return SDC_OK;
}

static int gc_supports(sdc_alg alg)
{
    switch (alg) {
    case SDC_ALG_AES_256_GCM:
    case SDC_ALG_CHACHA20_POLY1305:
    case SDC_ALG_SHA256:
    case SDC_ALG_SHA384:
    case SDC_ALG_SHA512:
    case SDC_ALG_SHA3_256:
    case SDC_ALG_SHA3_512:
    case SDC_ALG_ED25519:
    case SDC_ALG_ECDSA_P256_SHA256:
        return 1;
    default:
        return 0;
    }
}

static sdc_status gc_random(uint8_t *buf, size_t len)
{
    gcry_randomize(buf, len, GCRY_STRONG_RANDOM);
    return SDC_OK;
}

/* ------------------------------------------------------------------- AEAD */

static gcry_error_t aead_open(gcry_cipher_hd_t *h, sdc_alg alg,
                              const uint8_t *key, const uint8_t *nonce,
                              const uint8_t *aad, size_t aad_len)
{
    gcry_error_t e = alg == SDC_ALG_AES_256_GCM
        ? gcry_cipher_open(h, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0)
        : gcry_cipher_open(h, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_POLY1305, 0);
    if (e)
        return e;
    if ((e = gcry_cipher_setkey(*h, key, 32)) ||
        (e = gcry_cipher_setiv(*h, nonce, 12)) ||
        (e = gcry_cipher_authenticate(*h, aad, aad_len)) ||
        (e = gcry_cipher_final(*h))) {
        gcry_cipher_close(*h);
        *h = NULL;
    }
    return e;
}

static sdc_status gc_aead_encrypt(sdc_alg alg, const uint8_t *key,
                                  const uint8_t *nonce,
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *pt, size_t pt_len,
                                  uint8_t *ct, uint8_t *tag)
{
    gcry_cipher_hd_t h;
    if (aead_open(&h, alg, key, nonce, aad, aad_len))
        return SDC_ERR_PROVIDER;
    sdc_status st = SDC_ERR_PROVIDER;
    if ((pt_len == 0 || !gcry_cipher_encrypt(h, ct, pt_len, pt, pt_len)) &&
        !gcry_cipher_gettag(h, tag, 16))
        st = SDC_OK;
    gcry_cipher_close(h);
    return st;
}

static sdc_status gc_aead_decrypt(sdc_alg alg, const uint8_t *key,
                                  const uint8_t *nonce,
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *ct, size_t ct_len,
                                  const uint8_t *tag, uint8_t *pt)
{
    gcry_cipher_hd_t h;
    if (aead_open(&h, alg, key, nonce, aad, aad_len))
        return SDC_ERR_PROVIDER;
    sdc_status st = SDC_ERR_PROVIDER;
    if (ct_len == 0 || !gcry_cipher_decrypt(h, pt, ct_len, ct, ct_len)) {
        gcry_error_t e = gcry_cipher_checktag(h, tag, 16);
        st = !e ? SDC_OK
                : gcry_err_code(e) == GPG_ERR_CHECKSUM ? SDC_ERR_AUTH_FAILED
                                                       : SDC_ERR_PROVIDER;
    }
    gcry_cipher_close(h);
    return st;
}

/* ------------------------------------------------------------------- hash */

static int md_algo(sdc_alg alg)
{
    switch (alg) {
    case SDC_ALG_SHA256:   return GCRY_MD_SHA256;
    case SDC_ALG_SHA384:   return GCRY_MD_SHA384;
    case SDC_ALG_SHA512:   return GCRY_MD_SHA512;
    case SDC_ALG_SHA3_256: return GCRY_MD_SHA3_256;
    case SDC_ALG_SHA3_512: return GCRY_MD_SHA3_512;
    default:               return 0;
    }
}

static sdc_status gc_hash(sdc_alg alg, const uint8_t *in, size_t in_len,
                          uint8_t *out)
{
    static const uint8_t empty[1];
    gcry_md_hash_buffer(md_algo(alg), out, in ? in : empty, in_len);
    return SDC_OK;
}

const sdc_provider sdc_provider_gcrypt = {
    .name         = "gcrypt",
    .init         = gc_init,
    .supports     = gc_supports,
    .random       = gc_random,
    .aead_encrypt = gc_aead_encrypt,
    .aead_decrypt = gc_aead_decrypt,
    .hash         = gc_hash,
};
