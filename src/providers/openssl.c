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

/* ------------------------------------------------------------------- AEAD */

static const EVP_CIPHER *aead_cipher(sdc_alg alg)
{
    return alg == SDC_ALG_AES_256_GCM ? EVP_aes_256_gcm() : EVP_chacha20_poly1305();
}

/* EVP takes int lengths; process in chunks so size_t inputs are safe. */
static int update_chunks(EVP_CIPHER_CTX *c, int enc, uint8_t *out,
                         const uint8_t *in, size_t len)
{
    while (len) {
        int n = len > (INT_MAX / 2) ? (INT_MAX / 2) : (int)len, outl;
        int ok = enc ? EVP_EncryptUpdate(c, out, &outl, in, n)
                     : EVP_DecryptUpdate(c, out, &outl, in, n);
        if (!ok)
            return 0;
        if (out)
            out += outl;
        in += n;
        len -= (size_t)n;
    }
    return 1;
}

static sdc_status ossl_aead_encrypt(sdc_alg alg, const uint8_t *key,
                                    const uint8_t *nonce,
                                    const uint8_t *aad, size_t aad_len,
                                    const uint8_t *pt, size_t pt_len,
                                    uint8_t *ct, uint8_t *tag)
{
    sdc_status st = SDC_ERR_PROVIDER;
    int outl;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c)
        return SDC_ERR_NOMEM;
    if (EVP_EncryptInit_ex(c, aead_cipher(alg), NULL, key, nonce) == 1 &&
        update_chunks(c, 1, NULL, aad, aad_len) &&
        update_chunks(c, 1, ct, pt, pt_len) &&
        EVP_EncryptFinal_ex(c, ct + pt_len, &outl) == 1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1)
        st = SDC_OK;
    EVP_CIPHER_CTX_free(c);
    return st;
}

static sdc_status ossl_aead_decrypt(sdc_alg alg, const uint8_t *key,
                                    const uint8_t *nonce,
                                    const uint8_t *aad, size_t aad_len,
                                    const uint8_t *ct, size_t ct_len,
                                    const uint8_t *tag, uint8_t *pt)
{
    sdc_status st = SDC_ERR_PROVIDER;
    int outl;
    uint8_t tagbuf[16];
    memcpy(tagbuf, tag, sizeof(tagbuf));
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c)
        return SDC_ERR_NOMEM;
    if (EVP_DecryptInit_ex(c, aead_cipher(alg), NULL, key, nonce) == 1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 16, tagbuf) == 1 &&
        update_chunks(c, 0, NULL, aad, aad_len) &&
        update_chunks(c, 0, pt, ct, ct_len)) {
        st = EVP_DecryptFinal_ex(c, pt + ct_len, &outl) == 1 ? SDC_OK
                                                             : SDC_ERR_AUTH_FAILED;
    }
    EVP_CIPHER_CTX_free(c);
    return st;
}

/* ------------------------------------------------------------- hash / KDF */

static const EVP_MD *md_for(sdc_alg alg)
{
    switch (alg) {
    case SDC_ALG_SHA256:
    case SDC_ALG_HKDF_SHA256:
    case SDC_ALG_ECDSA_P256_SHA256: return EVP_sha256();
    case SDC_ALG_SHA384:            return EVP_sha384();
    case SDC_ALG_SHA512:
    case SDC_ALG_HKDF_SHA512:       return EVP_sha512();
    case SDC_ALG_SHA3_256:          return EVP_sha3_256();
    case SDC_ALG_SHA3_512:          return EVP_sha3_512();
    default:                        return NULL;
    }
}

static sdc_status ossl_hash(sdc_alg alg, const uint8_t *in, size_t in_len,
                            uint8_t *out)
{
    static const uint8_t empty[1];
    return EVP_Digest(in ? in : empty, in_len, out, NULL, md_for(alg), NULL) == 1
               ? SDC_OK : SDC_ERR_PROVIDER;
}

const sdc_provider sdc_provider_openssl = {
    .name         = "openssl",
    .supports     = ossl_supports,
    .random       = ossl_random,
    .aead_encrypt = ossl_aead_encrypt,
    .aead_decrypt = ossl_aead_decrypt,
    .hash         = ossl_hash,
};
