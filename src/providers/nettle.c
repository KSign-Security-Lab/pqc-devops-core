/* Nettle / Hogweed provider. SPDX-License-Identifier: Apache-2.0 */
#include <errno.h>
#include <stdlib.h>
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
    case SDC_ALG_AES_128_GCM:
    case SDC_ALG_CHACHA20_POLY1305:
    case SDC_ALG_SHA256:
    case SDC_ALG_SHA224:
    case SDC_ALG_SHA384:
    case SDC_ALG_SHA512:
    case SDC_ALG_SHA3_256:
    case SDC_ALG_SHA3_384:
    case SDC_ALG_SHA3_512:
    case SDC_ALG_HKDF_SHA256:
    case SDC_ALG_HKDF_SHA512:
    case SDC_ALG_HMAC_SHA256:
    case SDC_ALG_HMAC_SHA512:
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

/* nettle_random_func adapter. It cannot report errors, and continuing with
 * predictable randomness (e.g. an ECDSA nonce) would leak keys, so abort. */
static void ntl_rng(void *ctx, size_t len, uint8_t *dst)
{
    (void)ctx;
    if (ntl_random(dst, len) != SDC_OK)
        abort();
}

/* ------------------------------------------------------------------- AEAD */

static sdc_status ntl_aead_encrypt(sdc_alg alg, const uint8_t *key,
                                   const uint8_t *nonce,
                                   const uint8_t *aad, size_t aad_len,
                                   const uint8_t *pt, size_t pt_len,
                                   uint8_t *ct, uint8_t *tag)
{
    if (alg == SDC_ALG_AES_256_GCM) {
        struct gcm_aes256_ctx c;
        gcm_aes256_set_key(&c, key);
        gcm_aes256_set_iv(&c, 12, nonce);
        gcm_aes256_update(&c, aad_len, aad);
        gcm_aes256_encrypt(&c, pt_len, ct, pt);
        gcm_aes256_digest(&c, 16, tag);
        sdc_memzero(&c, sizeof(c));
    } else if (alg == SDC_ALG_AES_128_GCM) {
        struct gcm_aes128_ctx c;
        gcm_aes128_set_key(&c, key);
        gcm_aes128_set_iv(&c, 12, nonce);
        gcm_aes128_update(&c, aad_len, aad);
        gcm_aes128_encrypt(&c, pt_len, ct, pt);
        gcm_aes128_digest(&c, 16, tag);
        sdc_memzero(&c, sizeof(c));
    } else {
        struct chacha_poly1305_ctx c;
        chacha_poly1305_set_key(&c, key);
        chacha_poly1305_set_nonce(&c, nonce);
        chacha_poly1305_update(&c, aad_len, aad);
        chacha_poly1305_encrypt(&c, pt_len, ct, pt);
        chacha_poly1305_digest(&c, 16, tag);
        sdc_memzero(&c, sizeof(c));
    }
    return SDC_OK;
}

static sdc_status ntl_aead_decrypt(sdc_alg alg, const uint8_t *key,
                                   const uint8_t *nonce,
                                   const uint8_t *aad, size_t aad_len,
                                   const uint8_t *ct, size_t ct_len,
                                   const uint8_t *tag, uint8_t *pt)
{
    uint8_t calc[16];
    if (alg == SDC_ALG_AES_256_GCM) {
        struct gcm_aes256_ctx c;
        gcm_aes256_set_key(&c, key);
        gcm_aes256_set_iv(&c, 12, nonce);
        gcm_aes256_update(&c, aad_len, aad);
        gcm_aes256_decrypt(&c, ct_len, pt, ct);
        gcm_aes256_digest(&c, 16, calc);
        sdc_memzero(&c, sizeof(c));
    } else if (alg == SDC_ALG_AES_128_GCM) {
        struct gcm_aes128_ctx c;
        gcm_aes128_set_key(&c, key);
        gcm_aes128_set_iv(&c, 12, nonce);
        gcm_aes128_update(&c, aad_len, aad);
        gcm_aes128_decrypt(&c, ct_len, pt, ct);
        gcm_aes128_digest(&c, 16, calc);
        sdc_memzero(&c, sizeof(c));
    } else {
        struct chacha_poly1305_ctx c;
        chacha_poly1305_set_key(&c, key);
        chacha_poly1305_set_nonce(&c, nonce);
        chacha_poly1305_update(&c, aad_len, aad);
        chacha_poly1305_decrypt(&c, ct_len, pt, ct);
        chacha_poly1305_digest(&c, 16, calc);
        sdc_memzero(&c, sizeof(c));
    }
    return memeql_sec(calc, tag, 16) ? SDC_OK : SDC_ERR_AUTH_FAILED;
}

/* ------------------------------------------------------------- hash / KDF */

static sdc_status ntl_hash(sdc_alg alg, const uint8_t *in, size_t in_len,
                           uint8_t *out)
{
    switch (alg) {
    case SDC_ALG_SHA256: {
        struct sha256_ctx c;
        sha256_init(&c); sha256_update(&c, in_len, in); sha256_digest(&c, 32, out);
        break;
    }
    case SDC_ALG_SHA224: {
        struct sha224_ctx c;
        sha224_init(&c); sha224_update(&c, in_len, in); sha224_digest(&c, 28, out);
        break;
    }
    case SDC_ALG_SHA384: {
        struct sha384_ctx c;
        sha384_init(&c); sha384_update(&c, in_len, in); sha384_digest(&c, 48, out);
        break;
    }
    case SDC_ALG_SHA512: {
        struct sha512_ctx c;
        sha512_init(&c); sha512_update(&c, in_len, in); sha512_digest(&c, 64, out);
        break;
    }
    case SDC_ALG_SHA3_256: {
        struct sha3_256_ctx c;
        sha3_256_init(&c); sha3_256_update(&c, in_len, in); sha3_256_digest(&c, 32, out);
        break;
    }
    case SDC_ALG_SHA3_384: {
        struct sha3_384_ctx c;
        sha3_384_init(&c); sha3_384_update(&c, in_len, in); sha3_384_digest(&c, 48, out);
        break;
    }
    case SDC_ALG_SHA3_512: {
        struct sha3_512_ctx c;
        sha3_512_init(&c); sha3_512_update(&c, in_len, in); sha3_512_digest(&c, 64, out);
        break;
    }
    default:
        return SDC_ERR_UNSUPPORTED;
    }
    return SDC_OK;
}

static sdc_status ntl_hkdf(sdc_alg alg, const uint8_t *ikm, size_t ikm_len,
                           const uint8_t *salt, size_t salt_len,
                           const uint8_t *info, size_t info_len,
                           uint8_t *out, size_t out_len)
{
    uint8_t prk[SHA512_DIGEST_SIZE];
    if (alg == SDC_ALG_HKDF_SHA256) {
        struct hmac_sha256_ctx c;
        hmac_sha256_set_key(&c, salt_len, salt);
        hkdf_extract(&c, (nettle_hash_update_func *)hmac_sha256_update,
                     (nettle_hash_digest_func *)hmac_sha256_digest,
                     SHA256_DIGEST_SIZE, ikm_len, ikm, prk);
        hmac_sha256_set_key(&c, SHA256_DIGEST_SIZE, prk);
        hkdf_expand(&c, (nettle_hash_update_func *)hmac_sha256_update,
                    (nettle_hash_digest_func *)hmac_sha256_digest,
                    SHA256_DIGEST_SIZE, info_len, info, out_len, out);
        sdc_memzero(&c, sizeof(c));
    } else {
        struct hmac_sha512_ctx c;
        hmac_sha512_set_key(&c, salt_len, salt);
        hkdf_extract(&c, (nettle_hash_update_func *)hmac_sha512_update,
                     (nettle_hash_digest_func *)hmac_sha512_digest,
                     SHA512_DIGEST_SIZE, ikm_len, ikm, prk);
        hmac_sha512_set_key(&c, SHA512_DIGEST_SIZE, prk);
        hkdf_expand(&c, (nettle_hash_update_func *)hmac_sha512_update,
                    (nettle_hash_digest_func *)hmac_sha512_digest,
                    SHA512_DIGEST_SIZE, info_len, info, out_len, out);
        sdc_memzero(&c, sizeof(c));
    }
    sdc_memzero(prk, sizeof(prk));
    return SDC_OK;
}

static sdc_status ntl_mac(sdc_alg alg, const uint8_t *key, size_t key_len,
                          const uint8_t *msg, size_t msg_len, uint8_t *out)
{
    if (alg == SDC_ALG_HMAC_SHA256) {
        struct hmac_sha256_ctx c;
        hmac_sha256_set_key(&c, key_len, key);
        hmac_sha256_update(&c, msg_len, msg);
        hmac_sha256_digest(&c, SHA256_DIGEST_SIZE, out);
        sdc_memzero(&c, sizeof(c));
    } else {
        struct hmac_sha512_ctx c;
        hmac_sha512_set_key(&c, key_len, key);
        hmac_sha512_update(&c, msg_len, msg);
        hmac_sha512_digest(&c, SHA512_DIGEST_SIZE, out);
        sdc_memzero(&c, sizeof(c));
    }
    return SDC_OK;
}

/* ------------------------------------------------------------- signatures */

static void mpz_to_be32(uint8_t out[32], const mpz_t v)
{
    size_t n = 0;
    memset(out, 0, 32);
    if (mpz_sizeinbase(v, 256) <= 32 && mpz_sgn(v) > 0) {
        uint8_t tmp[32];
        mpz_export(tmp, &n, 1, 1, 1, 0, v);
        memcpy(out + 32 - n, tmp, n);
        sdc_memzero(tmp, sizeof(tmp));
    }
}

static int ecc_pub_to_raw(const struct ecc_point *p, uint8_t out[65])
{
    mpz_t x, y;
    mpz_inits(x, y, NULL);
    ecc_point_get(p, x, y);
    out[0] = 0x04;
    mpz_to_be32(out + 1, x);
    mpz_to_be32(out + 33, y);
    mpz_clears(x, y, NULL);
    return 1;
}

static int ecc_pub_from_raw(struct ecc_point *p, const uint8_t in[65])
{
    int ok;
    mpz_t x, y;
    if (in[0] != 0x04)
        return 0;
    mpz_inits(x, y, NULL);
    mpz_import(x, 32, 1, 1, 1, 0, in + 1);
    mpz_import(y, 32, 1, 1, 1, 0, in + 33);
    ok = ecc_point_set(p, x, y); /* checks the point is on the curve */
    mpz_clears(x, y, NULL);
    return ok;
}

static sdc_status ntl_sig_keypair(sdc_alg alg, uint8_t *pk, uint8_t *sk)
{
    if (alg == SDC_ALG_ED25519) {
        sdc_status st = ntl_random(sk, 32);
        if (st == SDC_OK)
            ed25519_sha512_public_key(pk, sk);
        return st;
    }

    const struct ecc_curve *curve = nettle_get_secp_256r1();
    struct ecc_point pub;
    struct ecc_scalar key;
    mpz_t d;
    ecc_point_init(&pub, curve);
    ecc_scalar_init(&key, curve);
    mpz_init(d);
    ecdsa_generate_keypair(&pub, &key, NULL, ntl_rng);
    ecc_scalar_get(&key, d);
    mpz_to_be32(sk, d);
    ecc_pub_to_raw(&pub, pk);
    mpz_clear(d);
    ecc_scalar_clear(&key);
    ecc_point_clear(&pub);
    return SDC_OK;
}

static sdc_status ntl_sign(sdc_alg alg, const uint8_t *sk,
                           const uint8_t *msg, size_t msg_len,
                           uint8_t *sig, size_t *sig_len)
{
    if (alg == SDC_ALG_ED25519) {
        uint8_t pub[32];
        ed25519_sha512_public_key(pub, sk);
        ed25519_sha512_sign(pub, sk, msg_len, msg, sig);
        *sig_len = 64;
        return SDC_OK;
    }

    sdc_status st = SDC_ERR_INVALID_ARG;
    const struct ecc_curve *curve = nettle_get_secp_256r1();
    struct ecc_scalar key;
    struct dsa_signature ds;
    uint8_t digest[32];
    mpz_t d;
    ntl_hash(SDC_ALG_SHA256, msg, msg_len, digest);
    ecc_scalar_init(&key, curve);
    dsa_signature_init(&ds);
    mpz_init(d);
    mpz_import(d, 32, 1, 1, 1, 0, sk);
    if (ecc_scalar_set(&key, d)) { /* rejects 0 and >= n */
        ecdsa_sign(&key, NULL, ntl_rng, sizeof(digest), digest, &ds);
        mpz_to_be32(sig, ds.r);
        mpz_to_be32(sig + 32, ds.s);
        *sig_len = 64;
        st = SDC_OK;
    }
    mpz_clear(d);
    dsa_signature_clear(&ds);
    ecc_scalar_clear(&key);
    return st;
}

static sdc_status ntl_verify(sdc_alg alg, const uint8_t *pk,
                             const uint8_t *msg, size_t msg_len,
                             const uint8_t *sig, size_t sig_len)
{
    if (sig_len != 64)
        return SDC_ERR_VERIFY_FAILED;
    if (alg == SDC_ALG_ED25519)
        return ed25519_sha512_verify(pk, msg_len, msg, sig) ? SDC_OK
                                                            : SDC_ERR_VERIFY_FAILED;

    sdc_status st = SDC_ERR_VERIFY_FAILED;
    const struct ecc_curve *curve = nettle_get_secp_256r1();
    struct ecc_point pub;
    struct dsa_signature ds;
    uint8_t digest[32];
    ntl_hash(SDC_ALG_SHA256, msg, msg_len, digest);
    ecc_point_init(&pub, curve);
    dsa_signature_init(&ds);
    mpz_import(ds.r, 32, 1, 1, 1, 0, sig);
    mpz_import(ds.s, 32, 1, 1, 1, 0, sig + 32);
    if (ecc_pub_from_raw(&pub, pk) &&
        ecdsa_verify(&pub, sizeof(digest), digest, &ds))
        st = SDC_OK;
    dsa_signature_clear(&ds);
    ecc_point_clear(&pub);
    return st;
}

const sdc_provider sdc_provider_nettle = {
    .name         = "nettle",
    .supports     = ntl_supports,
    .random       = ntl_random,
    .aead_encrypt = ntl_aead_encrypt,
    .aead_decrypt = ntl_aead_decrypt,
    .hash         = ntl_hash,
    .hkdf         = ntl_hkdf,
    .mac          = ntl_mac,
    .sig_keypair  = ntl_sig_keypair,
    .sign         = ntl_sign,
    .verify       = ntl_verify,
};
