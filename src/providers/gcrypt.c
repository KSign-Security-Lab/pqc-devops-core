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
    case SDC_ALG_AES_128_GCM:
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
    gcry_error_t e;
    size_t key_len = 32;
    switch (alg) {
    case SDC_ALG_AES_256_GCM:
        e = gcry_cipher_open(h, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0);
        break;
    case SDC_ALG_AES_128_GCM:
        e = gcry_cipher_open(h, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 0);
        key_len = 16;
        break;
    default:
        e = gcry_cipher_open(h, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_POLY1305, 0);
        break;
    }
    if (e)
        return e;
    if ((e = gcry_cipher_setkey(*h, key, key_len)) ||
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

/* ------------------------------------------------------------- signatures */

/* Copy an S-expression token's value into a fixed big-endian buffer. */
static int sexp_get_fixed(gcry_sexp_t s, const char *tok, uint8_t *out, size_t n,
                          int as_mpi)
{
    int ok = 0;
    gcry_sexp_t t = gcry_sexp_find_token(s, tok, 0);
    if (!t)
        return 0;
    if (as_mpi) {
        gcry_mpi_t m = gcry_sexp_nth_mpi(t, 1, GCRYMPI_FMT_USG);
        size_t w = 0;
        if (m && (gcry_mpi_get_nbits(m) + 7) / 8 <= n) {
            memset(out, 0, n);
            if (!gcry_mpi_print(GCRYMPI_FMT_USG, out, n, &w, m)) {
                memmove(out + n - w, out, w);
                memset(out, 0, n - w);
                ok = 1;
            }
        }
        gcry_mpi_release(m);
    } else {
        size_t len = 0;
        const char *d = gcry_sexp_nth_data(t, 1, &len);
        if (d && len <= n) {
            memset(out, 0, n);
            memcpy(out + n - len, d, len);
            ok = 1;
        }
    }
    gcry_sexp_release(t);
    return ok;
}

static gcry_mpi_t mpi_from(const uint8_t *buf, size_t n)
{
    gcry_mpi_t m = NULL;
    return gcry_mpi_scan(&m, GCRYMPI_FMT_USG, buf, n, NULL) ? NULL : m;
}

static sdc_status gc_sig_keypair(sdc_alg alg, uint8_t *pk, uint8_t *sk)
{
    gcry_sexp_t params = NULL, kp = NULL;
    sdc_status st = SDC_ERR_PROVIDER;
    int ed = alg == SDC_ALG_ED25519;
    const char *spec = ed ? "(genkey (ecc (curve Ed25519)(flags eddsa)))"
                          : "(genkey (ecc (curve \"NIST P-256\")))";
    if (gcry_sexp_new(&params, spec, 0, 1) || gcry_pk_genkey(&kp, params))
        goto out;
    if (ed) {
        /* q may carry a 0x40 "compact" prefix. */
        uint8_t q[33];
        gcry_sexp_t t = gcry_sexp_find_token(kp, "q", 0);
        size_t len = 0;
        const char *d = t ? gcry_sexp_nth_data(t, 1, &len) : NULL;
        if (d && (len == 32 || (len == 33 && (uint8_t)d[0] == 0x40))) {
            memcpy(q, d, len);
            memcpy(pk, len == 33 ? q + 1 : q, 32);
            if (sexp_get_fixed(kp, "d", sk, 32, 0))
                st = SDC_OK;
        }
        gcry_sexp_release(t);
    } else if (sexp_get_fixed(kp, "q", pk, 65, 0) && pk[0] == 0x04 &&
               sexp_get_fixed(kp, "d", sk, 32, 1)) {
        st = SDC_OK;
    }
out:
    gcry_sexp_release(kp);
    gcry_sexp_release(params);
    return st;
}

static sdc_status gc_sign(sdc_alg alg, const uint8_t *sk,
                          const uint8_t *msg, size_t msg_len,
                          uint8_t *sig, size_t *sig_len)
{
    static const uint8_t empty[1];
    gcry_sexp_t key = NULL, data = NULL, s = NULL;
    gcry_mpi_t d = NULL;
    sdc_status st = SDC_ERR_PROVIDER;
    gcry_error_t e;

    if (!msg)
        msg = empty;
    if (alg == SDC_ALG_ED25519) {
        e = gcry_sexp_build(&key, NULL,
                            "(private-key (ecc (curve Ed25519)(flags eddsa)(d %b)))",
                            32, sk);
        if (!e)
            e = gcry_sexp_build(&data, NULL,
                                "(data (flags eddsa)(hash-algo sha512)(value %b))",
                                (int)msg_len, msg);
    } else {
        uint8_t digest[32];
        gc_hash(SDC_ALG_SHA256, msg, msg_len, digest);
        d = mpi_from(sk, 32);
        e = d ? gcry_sexp_build(&key, NULL,
                                "(private-key (ecc (curve \"NIST P-256\")(d %m)))", d)
              : GPG_ERR_INV_VALUE;
        if (!e)
            e = gcry_sexp_build(&data, NULL,
                                "(data (flags rfc6979)(hash sha256 %b))", 32, digest);
    }
    if (e || gcry_pk_sign(&s, data, key))
        goto out;

    int as_mpi = alg != SDC_ALG_ED25519;
    if (sexp_get_fixed(s, "r", sig, 32, as_mpi) &&
        sexp_get_fixed(s, "s", sig + 32, 32, as_mpi)) {
        *sig_len = 64;
        st = SDC_OK;
    }
out:
    gcry_mpi_release(d);
    gcry_sexp_release(s);
    gcry_sexp_release(data);
    gcry_sexp_release(key);
    return st;
}

static sdc_status gc_verify(sdc_alg alg, const uint8_t *pk,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t *sig, size_t sig_len)
{
    static const uint8_t empty[1];
    gcry_sexp_t key = NULL, data = NULL, s = NULL;
    gcry_mpi_t r = NULL, sv = NULL;
    sdc_status st = SDC_ERR_PROVIDER;
    gcry_error_t e;

    if (sig_len != 64)
        return SDC_ERR_VERIFY_FAILED;
    if (!msg)
        msg = empty;
    if (alg == SDC_ALG_ED25519) {
        e = gcry_sexp_build(&key, NULL,
                            "(public-key (ecc (curve Ed25519)(flags eddsa)(q %b)))",
                            32, pk);
        if (!e)
            e = gcry_sexp_build(&data, NULL,
                                "(data (flags eddsa)(hash-algo sha512)(value %b))",
                                (int)msg_len, msg);
        if (!e)
            e = gcry_sexp_build(&s, NULL, "(sig-val (eddsa (r %b)(s %b)))",
                                32, sig, 32, sig + 32);
    } else {
        uint8_t digest[32];
        gc_hash(SDC_ALG_SHA256, msg, msg_len, digest);
        r = mpi_from(sig, 32);
        sv = mpi_from(sig + 32, 32);
        e = gcry_sexp_build(&key, NULL,
                            "(public-key (ecc (curve \"NIST P-256\")(q %b)))", 65, pk);
        if (!e)
            e = gcry_sexp_build(&data, NULL, "(data (flags raw)(value %b))",
                                32, digest);
        if (!e)
            e = r && sv ? gcry_sexp_build(&s, NULL, "(sig-val (ecdsa (r %m)(s %m)))",
                                          r, sv)
                        : GPG_ERR_INV_VALUE;
    }
    if (!e) {
        e = gcry_pk_verify(s, data, key);
        /* Any verification-time error (bad sig, invalid point, ...) means
         * the signature is not valid for this key. */
        st = e ? SDC_ERR_VERIFY_FAILED : SDC_OK;
    }
    gcry_mpi_release(r);
    gcry_mpi_release(sv);
    gcry_sexp_release(s);
    gcry_sexp_release(data);
    gcry_sexp_release(key);
    return st;
}

const sdc_provider sdc_provider_gcrypt = {
    .name         = "gcrypt",
    .init         = gc_init,
    .supports     = gc_supports,
    .random       = gc_random,
    .aead_encrypt = gc_aead_encrypt,
    .aead_decrypt = gc_aead_decrypt,
    .hash         = gc_hash,
    .sig_keypair  = gc_sig_keypair,
    .sign         = gc_sign,
    .verify       = gc_verify,
};
