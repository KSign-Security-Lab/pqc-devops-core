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
    case SDC_ALG_AES_128_GCM:
    case SDC_ALG_CHACHA20_POLY1305:
    case SDC_ALG_SHA256:
    case SDC_ALG_SHA224:
    case SDC_ALG_SHA384:
    case SDC_ALG_SHA512:
    case SDC_ALG_SHA3_256:
    case SDC_ALG_SHA3_384:
    case SDC_ALG_SHA3_512:
    case SDC_ALG_BLAKE2B_512:
    case SDC_ALG_HKDF_SHA256:
    case SDC_ALG_HKDF_SHA512:
    case SDC_ALG_HMAC_SHA256:
    case SDC_ALG_HMAC_SHA512:
    case SDC_ALG_PBKDF2_SHA256:
    case SDC_ALG_ED25519:
    case SDC_ALG_ECDSA_P256_SHA256:
    case SDC_ALG_X25519:
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
    switch (alg) {
    case SDC_ALG_AES_256_GCM: return EVP_aes_256_gcm();
    case SDC_ALG_AES_128_GCM: return EVP_aes_128_gcm();
    default:                  return EVP_chacha20_poly1305();
    }
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
    case SDC_ALG_SHA224:            return EVP_sha224();
    case SDC_ALG_SHA384:            return EVP_sha384();
    case SDC_ALG_SHA512:
    case SDC_ALG_HKDF_SHA512:       return EVP_sha512();
    case SDC_ALG_SHA3_256:          return EVP_sha3_256();
    case SDC_ALG_SHA3_384:          return EVP_sha3_384();
    case SDC_ALG_SHA3_512:          return EVP_sha3_512();
    case SDC_ALG_BLAKE2B_512:       return EVP_blake2b512();
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

static sdc_status ossl_mac(sdc_alg alg, const uint8_t *key, size_t key_len,
                           const uint8_t *msg, size_t msg_len, uint8_t *out)
{
    static const uint8_t empty[1];
    size_t n = 0, want = alg == SDC_ALG_HMAC_SHA256 ? 32 : 64;
    if (!EVP_Q_mac(NULL, "HMAC", NULL, alg == SDC_ALG_HMAC_SHA256 ? "SHA256" : "SHA512",
                   NULL, key ? key : empty, key_len, msg ? msg : empty, msg_len,
                   out, want, &n) || n != want)
        return SDC_ERR_PROVIDER;
    return SDC_OK;
}

static sdc_status ossl_pbkdf2(sdc_alg alg, const uint8_t *pw, size_t pw_len,
                              const uint8_t *salt, size_t salt_len,
                              uint32_t iterations, uint8_t *out, size_t out_len)
{
    static const uint8_t empty[1];
    (void)alg;
    if (iterations > INT_MAX)
        return SDC_ERR_INVALID_ARG;
    return PKCS5_PBKDF2_HMAC(pw ? (const char *)pw : (const char *)empty, (int)pw_len,
                             salt ? salt : empty, (int)salt_len, (int)iterations,
                             EVP_sha256(), (int)out_len, out) == 1
               ? SDC_OK : SDC_ERR_PROVIDER;
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

static sdc_status ossl_sig_keypair(sdc_alg alg, uint8_t *pk, uint8_t *sk)
{
    sdc_status st = SDC_ERR_PROVIDER;
    EVP_PKEY *pkey = NULL;
    if (alg == SDC_ALG_ED25519) {
        size_t pl = 32, sl = 32;
        pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
        if (pkey && EVP_PKEY_get_raw_public_key(pkey, pk, &pl) == 1 &&
            EVP_PKEY_get_raw_private_key(pkey, sk, &sl) == 1 && pl == 32 && sl == 32)
            st = SDC_OK;
    } else {
        /* Export only the scalar and recompute the point: OpenSSL 3.0.x
         * returns a zero length for the OSSL_PKEY_PARAM_PUB_KEY query. */
        BIGNUM *d = NULL;
        pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
        if (pkey && EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &d) == 1 &&
            BN_bn2binpad(d, sk, 32) == 32 && ec_pub_from_priv(sk, pk))
            st = SDC_OK;
        BN_clear_free(d);
    }
    EVP_PKEY_free(pkey);
    return st;
}

static sdc_status digest_sign(EVP_PKEY *pkey, const EVP_MD *md,
                              const uint8_t *msg, size_t msg_len,
                              uint8_t *sig, size_t *sig_len)
{
    static const uint8_t empty[1];
    sdc_status st = SDC_ERR_PROVIDER;
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    if (mc && EVP_DigestSignInit(mc, NULL, md, NULL, pkey) == 1 &&
        EVP_DigestSign(mc, sig, sig_len, msg ? msg : empty, msg_len) == 1)
        st = SDC_OK;
    EVP_MD_CTX_free(mc);
    return st;
}

static sdc_status ossl_sign(sdc_alg alg, const uint8_t *sk,
                            const uint8_t *msg, size_t msg_len,
                            uint8_t *sig, size_t *sig_len)
{
    sdc_status st = SDC_ERR_PROVIDER;
    if (alg == SDC_ALG_ED25519) {
        EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, sk, 32);
        if (pkey)
            st = digest_sign(pkey, NULL, msg, msg_len, sig, sig_len);
        EVP_PKEY_free(pkey);
        return st;
    }

    /* ECDSA: DER signature -> fixed r||s. */
    uint8_t pub[65], der[80];
    size_t der_len = sizeof(der);
    if (!ec_pub_from_priv(sk, pub))
        return SDC_ERR_INVALID_ARG;
    EVP_PKEY *pkey = ec_from_raw(pub, sizeof(pub), sk);
    if (pkey && digest_sign(pkey, EVP_sha256(), msg, msg_len, der, &der_len) == SDC_OK) {
        const uint8_t *q = der;
        ECDSA_SIG *es = d2i_ECDSA_SIG(NULL, &q, (long)der_len);
        const BIGNUM *r, *s;
        if (es) {
            ECDSA_SIG_get0(es, &r, &s);
            if (BN_bn2binpad(r, sig, 32) == 32 && BN_bn2binpad(s, sig + 32, 32) == 32) {
                *sig_len = 64;
                st = SDC_OK;
            }
            ECDSA_SIG_free(es);
        }
    }
    EVP_PKEY_free(pkey);
    return st;
}

static sdc_status digest_verify(EVP_PKEY *pkey, const EVP_MD *md,
                                const uint8_t *msg, size_t msg_len,
                                const uint8_t *sig, size_t sig_len)
{
    static const uint8_t empty[1];
    sdc_status st = SDC_ERR_PROVIDER;
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    if (mc && EVP_DigestVerifyInit(mc, NULL, md, NULL, pkey) == 1)
        st = EVP_DigestVerify(mc, sig, sig_len, msg ? msg : empty, msg_len) == 1
                 ? SDC_OK : SDC_ERR_VERIFY_FAILED;
    EVP_MD_CTX_free(mc);
    return st;
}

static sdc_status ossl_verify(sdc_alg alg, const uint8_t *pk,
                              const uint8_t *msg, size_t msg_len,
                              const uint8_t *sig, size_t sig_len)
{
    sdc_status st;
    if (alg == SDC_ALG_ED25519) {
        if (sig_len != 64)
            return SDC_ERR_VERIFY_FAILED;
        EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pk, 32);
        st = pkey ? digest_verify(pkey, NULL, msg, msg_len, sig, sig_len)
                  : SDC_ERR_VERIFY_FAILED;
        EVP_PKEY_free(pkey);
        return st;
    }

    if (sig_len != 64)
        return SDC_ERR_VERIFY_FAILED;
    EVP_PKEY *pkey = ec_from_raw(pk, 65, NULL);
    if (!pkey)
        return SDC_ERR_VERIFY_FAILED; /* invalid / off-curve public key */
    st = SDC_ERR_PROVIDER;
    ECDSA_SIG *es = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(sig, 32, NULL), *s = BN_bin2bn(sig + 32, 32, NULL);
    uint8_t *der = NULL;
    int der_len;
    if (es && r && s && ECDSA_SIG_set0(es, r, s) == 1) {
        r = s = NULL; /* owned by es */
        der_len = i2d_ECDSA_SIG(es, &der);
        if (der_len > 0)
            st = digest_verify(pkey, EVP_sha256(), msg, msg_len, der, (size_t)der_len);
    }
    OPENSSL_free(der);
    BN_free(r);
    BN_free(s);
    ECDSA_SIG_free(es);
    EVP_PKEY_free(pkey);
    return st;
}

/* ---------------------------------------------------------- key agreement */

static sdc_status ossl_kex_keypair(sdc_alg alg, uint8_t *pk, uint8_t *sk)
{
    (void)alg;
    size_t pl = 32, sl = 32;
    sdc_status st = SDC_ERR_PROVIDER;
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    if (pkey && EVP_PKEY_get_raw_public_key(pkey, pk, &pl) == 1 &&
        EVP_PKEY_get_raw_private_key(pkey, sk, &sl) == 1 && pl == 32 && sl == 32)
        st = SDC_OK;
    EVP_PKEY_free(pkey);
    return st;
}

static sdc_status ossl_kex_derive(sdc_alg alg, const uint8_t *sk,
                                  const uint8_t *peer_pk, uint8_t *ss)
{
    (void)alg;
    sdc_status st = SDC_ERR_PROVIDER;
    size_t n = 32;
    EVP_PKEY *self = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, 32);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pk, 32);
    EVP_PKEY_CTX *pc = self ? EVP_PKEY_CTX_new(self, NULL) : NULL;
    if (pc && peer && EVP_PKEY_derive_init(pc) == 1) {
        /* set_peer/derive fail for low-order peer points */
        st = EVP_PKEY_derive_set_peer(pc, peer) == 1 &&
             EVP_PKEY_derive(pc, ss, &n) == 1 && n == 32
                 ? SDC_OK : SDC_ERR_INVALID_ARG;
    }
    EVP_PKEY_CTX_free(pc);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(self);
    return st;
}

const sdc_provider sdc_provider_openssl = {
    .name         = "openssl",
    .supports     = ossl_supports,
    .random       = ossl_random,
    .aead_encrypt = ossl_aead_encrypt,
    .aead_decrypt = ossl_aead_decrypt,
    .hash         = ossl_hash,
    .hkdf         = ossl_hkdf,
    .mac          = ossl_mac,
    .pbkdf2       = ossl_pbkdf2,
    .sig_keypair  = ossl_sig_keypair,
    .sign         = ossl_sign,
    .verify       = ossl_verify,
    .kex_keypair  = ossl_kex_keypair,
    .kex_derive   = ossl_kex_derive,
};
