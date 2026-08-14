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

static sdc_status ossl_hkdf(sdc_alg alg, const uint8_t *ikm, size_t ikm_len,
                            const uint8_t *salt, size_t salt_len,
                            const uint8_t *info, size_t info_len,
                            uint8_t *out, size_t out_len)
{
    static uint8_t empty[1];
    sdc_status st = SDC_ERR_PROVIDER;
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kc = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
    if (kc) {
        OSSL_PARAM params[5], *p = params;
        *p++ = OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST,
            (char *)(alg == SDC_ALG_HKDF_SHA256 ? "SHA256" : "SHA512"), 0);
        *p++ = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY, ikm ? (void *)ikm : empty, ikm_len);
        if (salt_len)
            *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                     (void *)salt, salt_len);
        if (info_len)
            *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                     (void *)info, info_len);
        *p = OSSL_PARAM_construct_end();
        if (EVP_KDF_derive(kc, out, out_len, params) == 1)
            st = SDC_OK;
    }
    EVP_KDF_CTX_free(kc);
    EVP_KDF_free(kdf);
    return st;
}

/* ------------------------------------------------------------- signatures */

/* Build an EC P-256 EVP_PKEY from raw public point and optional scalar. */
static EVP_PKEY *ec_from_raw(const uint8_t *pub, size_t pub_len,
                             const uint8_t *priv)
{
    EVP_PKEY *pkey = NULL;
    BIGNUM *d = NULL;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *pc = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!bld || !pc)
        goto out;
    if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                         "prime256v1", 0) ||
        !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                          pub, pub_len))
        goto out;
    if (priv) {
        d = BN_secure_new();
        if (!d || !BN_bin2bn(priv, 32, d) ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, d))
            goto out;
    }
    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params || EVP_PKEY_fromdata_init(pc) != 1 ||
        EVP_PKEY_fromdata(pc, &pkey, priv ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
                          params) != 1)
        pkey = NULL;
out:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_clear_free(d);
    EVP_PKEY_CTX_free(pc);
    return pkey;
}

/* Derive the uncompressed public point from a P-256 scalar. */
static int ec_pub_from_priv(const uint8_t *priv, uint8_t pub[65])
{
    int ok = 0;
    EC_GROUP *g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *pt = g ? EC_POINT_new(g) : NULL;
    BIGNUM *d = BN_secure_new();
    if (g && pt && d && BN_bin2bn(priv, 32, d) && !BN_is_zero(d) &&
        BN_cmp(d, EC_GROUP_get0_order(g)) < 0 &&
        EC_POINT_mul(g, pt, d, NULL, NULL, NULL) == 1 &&
        EC_POINT_point2oct(g, pt, POINT_CONVERSION_UNCOMPRESSED, pub, 65, NULL) == 65)
        ok = 1;
    BN_clear_free(d);
    EC_POINT_free(pt);
    EC_GROUP_free(g);
    return ok;
}

const sdc_provider sdc_provider_openssl = {
    .name         = "openssl",
    .supports     = ossl_supports,
    .random       = ossl_random,
    .aead_encrypt = ossl_aead_encrypt,
    .aead_decrypt = ossl_aead_decrypt,
    .hash         = ossl_hash,
    .hkdf         = ossl_hkdf,
};
