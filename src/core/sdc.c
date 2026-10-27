/* Public API: contexts, validation and dispatch. SPDX-License-Identifier: Apache-2.0 */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "internal/provider.h"

#define SDC_MAX_PROVIDERS 16

struct sdc_ctx {
    size_t n;
    const sdc_provider *order[SDC_MAX_PROVIDERS];
};

/* ---------------------------------------------------------------- utilities */

const char *sdc_version(void) { return SDC_VERSION_STRING; }

const char *sdc_strerror(sdc_status st)
{
    switch (st) {
    case SDC_OK:                   return "success";
    case SDC_ERR_INVALID_ARG:      return "invalid argument";
    case SDC_ERR_UNSUPPORTED:      return "unsupported algorithm";
    case SDC_ERR_BUFFER_TOO_SMALL: return "output buffer too small";
    case SDC_ERR_AUTH_FAILED:      return "authentication failed";
    case SDC_ERR_VERIFY_FAILED:    return "signature verification failed";
    case SDC_ERR_PROVIDER:         return "provider error";
    case SDC_ERR_NO_PROVIDER:      return "no provider available for algorithm";
    case SDC_ERR_NOMEM:            return "out of memory";
    }
    return "unknown error";
}

void sdc_memzero(void *p, size_t len)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (len--)
        *v++ = 0;
}

int sdc_ct_equal(const void *a, const void *b, size_t len)
{
    const volatile uint8_t *x = a, *y = b;
    uint8_t d = 0;
    for (size_t i = 0; i < len; i++)
        d |= x[i] ^ y[i];
    return (int)(1u & (((unsigned)d - 1u) >> 8));
}

/* ----------------------------------------------------------------- contexts */

static sdc_status parse_pref(sdc_ctx *c, const char *pref)
{
    const char *s = pref;
    while (*s) {
        while (*s == ',' || *s == ' ')
            s++;
        const char *e = s;
        while (*e && *e != ',' && *e != ' ')
            e++;
        if (e > s) {
            const sdc_provider *p = sdc__provider_by_name(s, (size_t)(e - s));
            if (!p)
                return SDC_ERR_NO_PROVIDER;
            int dup = 0;
            for (size_t i = 0; i < c->n; i++)
                dup |= c->order[i] == p;
            if (!dup) {
                if (c->n == SDC_MAX_PROVIDERS)
                    return SDC_ERR_INVALID_ARG;
                c->order[c->n++] = p;
            }
        }
        s = e;
    }
    return c->n ? SDC_OK : SDC_ERR_INVALID_ARG;
}

static void default_order(sdc_ctx *c)
{
    c->n = 0;
    for (size_t i = 0; i < sdc__provider_count() && c->n < SDC_MAX_PROVIDERS; i++)
        c->order[c->n++] = sdc__provider_at(i);
}

sdc_status sdc_ctx_new(sdc_ctx **out, const char *pref)
{
    if (!out)
        return SDC_ERR_INVALID_ARG;
    *out = NULL;
    sdc_init();

    sdc_ctx *c = calloc(1, sizeof(*c));
    if (!c)
        return SDC_ERR_NOMEM;

    if (!pref) {
        const char *env = getenv("SDC_PROVIDER");
        if (env && *env)
            pref = env;
    }
    if (pref) {
        sdc_status st = parse_pref(c, pref);
        if (st != SDC_OK) {
            free(c);
            return st;
        }
    } else {
        default_order(c);
    }
    *out = c;
    return SDC_OK;
}

void sdc_ctx_free(sdc_ctx *ctx) { free(ctx); }

static const sdc_ctx *resolve_ctx(const sdc_ctx *ctx, sdc_ctx *tmp)
{
    if (ctx)
        return ctx;
    default_order(tmp);
    return tmp;
}

#define NO_OP ((size_t)-1)
#define OP(field) offsetof(sdc_provider, field)

/* True if provider p implements the vtable entry at offset `op`. */
static int has_op(const sdc_provider *p, size_t op)
{
    void (*fn)(void);
    if (op == NO_OP)
        return 1;
    memcpy(&fn, (const char *)p + op, sizeof(fn));
    return fn != NULL;
}

/* First provider in the context that supports `alg` and implements `op`.
 * Choosing per operation lets a provider implement only part of an
 * algorithm (e.g. verify but not keygen) and fall through to the next. */
static const sdc_provider *pick(const sdc_ctx *ctx, sdc_alg alg, size_t op)
{
    sdc_ctx tmp;
    ctx = resolve_ctx(ctx, &tmp);
    for (size_t i = 0; i < ctx->n; i++)
        if (ctx->order[i]->supports(alg) && has_op(ctx->order[i], op))
            return ctx->order[i];
    return NULL;
}

size_t sdc_ctx_provider_count(const sdc_ctx *ctx)
{
    sdc_ctx tmp;
    return resolve_ctx(ctx, &tmp)->n;
}

const char *sdc_ctx_provider_name(const sdc_ctx *ctx, size_t index)
{
    sdc_ctx tmp;
    ctx = resolve_ctx(ctx, &tmp);
    return index < ctx->n ? ctx->order[index]->name : NULL;
}

const char *sdc_ctx_provider_for(const sdc_ctx *ctx, sdc_alg alg)
{
    if (!sdc__alg_info(alg))
        return NULL;
    const sdc_provider *p = pick(ctx, alg, NO_OP);
    return p ? p->name : NULL;
}

/* --------------------------------------------------------------- validation */

/* Resolve alg info + provider for an operation of the given family. */
static sdc_status prepare(const sdc_ctx *ctx, sdc_alg alg, sdc_family fam,
                          size_t op, const sdc_alg_info **ai,
                          const sdc_provider **p)
{
    *ai = sdc__alg_info(alg);
    if (!*ai)
        return SDC_ERR_UNSUPPORTED;
    if ((*ai)->family != fam)
        return SDC_ERR_INVALID_ARG;
    *p = pick(ctx, alg, op);
    return *p ? SDC_OK : SDC_ERR_NO_PROVIDER;
}

/* Variable-length input: NULL only allowed when empty. */
#define CHECK_IN(ptr, len) \
    do { if (!(ptr) && (len)) return SDC_ERR_INVALID_ARG; } while (0)
/* Fixed-length input. */
#define CHECK_FIXED(ptr, len, want) \
    do { if (!(ptr) || (len) != (want)) return SDC_ERR_INVALID_ARG; } while (0)
/* In/out output buffer with a required size. */
#define CHECK_OUT(ptr, lenp, need)                                   \
    do {                                                             \
        if (!(lenp)) return SDC_ERR_INVALID_ARG;                     \
        if (*(lenp) < (need)) { *(lenp) = (need); return SDC_ERR_BUFFER_TOO_SMALL; } \
        if (!(ptr) && (need)) return SDC_ERR_INVALID_ARG;            \
    } while (0)

/* --------------------------------------------------------------- operations */

sdc_status sdc_random(const sdc_ctx *ctx, uint8_t *buf, size_t len)
{
    CHECK_IN(buf, len);
    if (!len)
        return SDC_OK;
    sdc_ctx tmp;
    ctx = resolve_ctx(ctx, &tmp);
    for (size_t i = 0; i < ctx->n; i++)
        if (has_op(ctx->order[i], OP(random)))
            return ctx->order[i]->random(buf, len);
    return SDC_ERR_NO_PROVIDER;
}

sdc_status sdc_aead_encrypt(const sdc_ctx *ctx, sdc_alg alg,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *pt, size_t pt_len,
                            uint8_t *out, size_t *out_len)
{
    const sdc_alg_info *ai;
    const sdc_provider *p;
    sdc_status st = prepare(ctx, alg, SDC_FAMILY_AEAD, OP(aead_encrypt), &ai, &p);
    if (st != SDC_OK)
        return st;
    CHECK_FIXED(key, key_len, ai->key_len);
    CHECK_FIXED(nonce, nonce_len, ai->nonce_len);
    CHECK_IN(aad, aad_len);
    CHECK_IN(pt, pt_len);
    if (pt_len > SIZE_MAX - ai->tag_len)
        return SDC_ERR_INVALID_ARG;
    CHECK_OUT(out, out_len, pt_len + ai->tag_len);

    st = p->aead_encrypt(alg, key, nonce, aad, aad_len, pt, pt_len,
                         out, out + pt_len);
    if (st == SDC_OK)
        *out_len = pt_len + ai->tag_len;
    else
        sdc_memzero(out, pt_len + ai->tag_len);
    return st;
}

sdc_status sdc_aead_decrypt(const sdc_ctx *ctx, sdc_alg alg,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *in, size_t in_len,
                            uint8_t *pt, size_t *pt_len)
{
    const sdc_alg_info *ai;
    const sdc_provider *p;
    sdc_status st = prepare(ctx, alg, SDC_FAMILY_AEAD, OP(aead_decrypt), &ai, &p);
    if (st != SDC_OK)
        return st;
    CHECK_FIXED(key, key_len, ai->key_len);
    CHECK_FIXED(nonce, nonce_len, ai->nonce_len);
    CHECK_IN(aad, aad_len);
    if (!in || in_len < ai->tag_len)
        return SDC_ERR_INVALID_ARG;
    size_t ct_len = in_len - ai->tag_len;
    CHECK_OUT(pt, pt_len, ct_len);

    st = p->aead_decrypt(alg, key, nonce, aad, aad_len, in, ct_len,
                         in + ct_len, pt);
    if (st == SDC_OK)
        *pt_len = ct_len;
    else if (ct_len)
        sdc_memzero(pt, ct_len);
    return st;
}

sdc_status sdc_hash(const sdc_ctx *ctx, sdc_alg alg,
                    const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t *out_len)
{
    const sdc_alg_info *ai;
    const sdc_provider *p;
    sdc_status st = prepare(ctx, alg, SDC_FAMILY_HASH, OP(hash), &ai, &p);
    if (st != SDC_OK)
        return st;
    CHECK_IN(in, in_len);
    CHECK_OUT(out, out_len, ai->digest_len);
    st = p->hash(alg, in, in_len, out);
    if (st == SDC_OK)
        *out_len = ai->digest_len;
    return st;
}

sdc_status sdc_hkdf(const sdc_ctx *ctx, sdc_alg alg,
                    const uint8_t *ikm, size_t ikm_len,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t out_len)
{
    const sdc_alg_info *ai;
    const sdc_provider *p;
    sdc_status st = prepare(ctx, alg, SDC_FAMILY_KDF, OP(hkdf), &ai, &p);
    if (st != SDC_OK)
        return st;
    CHECK_IN(ikm, ikm_len);
    CHECK_IN(salt, salt_len);
    CHECK_IN(info, info_len);
    if (!out || out_len == 0 || out_len > 255 * ai->digest_len)
        return SDC_ERR_INVALID_ARG;
    st = p->hkdf(alg, ikm, ikm_len, salt, salt_len, info, info_len, out, out_len);
    if (st != SDC_OK)
        sdc_memzero(out, out_len);
    return st;
}

sdc_status sdc_pbkdf2(const sdc_ctx *ctx, sdc_alg alg,
                      const uint8_t *password, size_t password_len,
                      const uint8_t *salt, size_t salt_len,
                      uint32_t iterations,
                      uint8_t *out, size_t out_len)
{
    const sdc_alg_info *ai;
    const sdc_provider *p;
    sdc_status st = prepare(ctx, alg, SDC_FAMILY_PBKDF, OP(pbkdf2), &ai, &p);
    if (st != SDC_OK)
        return st;
    CHECK_IN(password, password_len);
    CHECK_IN(salt, salt_len);
    /* cap lengths so every backend (some take int) can handle them */
    if (!out || out_len == 0 || out_len > (1u << 20) || iterations == 0 ||
        password_len > (1u << 20) || salt_len > (1u << 20))
        return SDC_ERR_INVALID_ARG;
    st = p->pbkdf2(alg, password, password_len, salt, salt_len, iterations,
                   out, out_len);
    if (st != SDC_OK)
        sdc_memzero(out, out_len);
    return st;
}

sdc_status sdc_mac(const sdc_ctx *ctx, sdc_alg alg,
                   const uint8_t *key, size_t key_len,
                   const uint8_t *msg, size_t msg_len,
                   uint8_t *out, size_t *out_len)
{
    const sdc_alg_info *ai;
    const sdc_provider *p;
    sdc_status st = prepare(ctx, alg, SDC_FAMILY_MAC, OP(mac), &ai, &p);
    if (st != SDC_OK)
        return st;
    CHECK_IN(key, key_len);
    CHECK_IN(msg, msg_len);
    CHECK_OUT(out, out_len, ai->digest_len);
    st = p->mac(alg, key, key_len, msg, msg_len, out);
    if (st == SDC_OK)
        *out_len = ai->digest_len;
    return st;
}

sdc_status sdc_mac_verify(const sdc_ctx *ctx, sdc_alg alg,
                          const uint8_t *key, size_t key_len,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *tag, size_t tag_len)
{
    uint8_t calc[64];
    size_t n = sizeof(calc);
    if (!tag)
        return SDC_ERR_INVALID_ARG;
    sdc_status st = sdc_mac(ctx, alg, key, key_len, msg, msg_len, calc, &n);
    if (st != SDC_OK)
        return st;
    st = tag_len == n && sdc_ct_equal(calc, tag, n) ? SDC_OK : SDC_ERR_VERIFY_FAILED;
    sdc_memzero(calc, sizeof(calc));
    return st;
}

static sdc_status keypair(const sdc_ctx *ctx, sdc_alg alg, sdc_family fam,
                          uint8_t *pk, size_t *pk_len,
                          uint8_t *sk, size_t *sk_len)
{
    const sdc_alg_info *ai;
    const sdc_provider *p;
    size_t op = fam == SDC_FAMILY_SIG ? OP(sig_keypair)
              : fam == SDC_FAMILY_KEM ? OP(kem_keypair) : OP(kex_keypair);
    sdc_status st = prepare(ctx, alg, fam, op, &ai, &p);
    if (st != SDC_OK)
        return st;
    if (!pk_len || !sk_len)
        return SDC_ERR_INVALID_ARG;
    if (*pk_len < ai->pk_len || *sk_len < ai->sk_len) {
        *pk_len = ai->pk_len;
        *sk_len = ai->sk_len;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    if (!pk || !sk)
        return SDC_ERR_INVALID_ARG;
    st = fam == SDC_FAMILY_SIG ? p->sig_keypair(alg, pk, sk)
       : fam == SDC_FAMILY_KEM ? p->kem_keypair(alg, pk, sk)
                               : p->kex_keypair(alg, pk, sk);
    if (st == SDC_OK) {
        *pk_len = ai->pk_len;
        *sk_len = ai->sk_len;
    } else {
        sdc_memzero(sk, ai->sk_len);
    }
    return st;
}

sdc_status sdc_sig_keypair(const sdc_ctx *ctx, sdc_alg alg,
                           uint8_t *pk, size_t *pk_len,
                           uint8_t *sk, size_t *sk_len)
{
    return keypair(ctx, alg, SDC_FAMILY_SIG, pk, pk_len, sk, sk_len);
}

sdc_status sdc_sign(const sdc_ctx *ctx, sdc_alg alg,
                    const uint8_t *sk, size_t sk_len,
                    const uint8_t *msg, size_t msg_len,
                    uint8_t *sig, size_t *sig_len)
{
    const sdc_alg_info *ai;
    const sdc_provider *p;
    sdc_status st = prepare(ctx, alg, SDC_FAMILY_SIG, OP(sign), &ai, &p);
    if (st != SDC_OK)
        return st;
    CHECK_FIXED(sk, sk_len, ai->sk_len);
    CHECK_IN(msg, msg_len);
    CHECK_OUT(sig, sig_len, ai->sig_len);
    size_t n = ai->sig_len;
    st = p->sign(alg, sk, msg, msg_len, sig, &n);
    if (st == SDC_OK)
        *sig_len = n;
    return st;
}

sdc_status sdc_verify(const sdc_ctx *ctx, sdc_alg alg,
                      const uint8_t *pk, size_t pk_len,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *sig, size_t sig_len)
{
    const sdc_alg_info *ai;
    const sdc_provider *p;
    sdc_status st = prepare(ctx, alg, SDC_FAMILY_SIG, OP(verify), &ai, &p);
    if (st != SDC_OK)
        return st;
    CHECK_FIXED(pk, pk_len, ai->pk_len);
    CHECK_IN(msg, msg_len);
    if (!sig)
        return SDC_ERR_INVALID_ARG;
    if (sig_len == 0 || sig_len > ai->sig_len)
        return SDC_ERR_VERIFY_FAILED;
    return p->verify(alg, pk, msg, msg_len, sig, sig_len);
}

sdc_status sdc_kem_keypair(const sdc_ctx *ctx, sdc_alg alg,
                           uint8_t *pk, size_t *pk_len,
                           uint8_t *sk, size_t *sk_len)
{
    return keypair(ctx, alg, SDC_FAMILY_KEM, pk, pk_len, sk, sk_len);
}

sdc_status sdc_kem_encaps(const sdc_ctx *ctx, sdc_alg alg,
                          const uint8_t *pk, size_t pk_len,
                          uint8_t *ct, size_t *ct_len,
                          uint8_t *ss, size_t *ss_len)
{
    const sdc_alg_info *ai;
    const sdc_provider *p;
    sdc_status st = prepare(ctx, alg, SDC_FAMILY_KEM, OP(kem_encaps), &ai, &p);
    if (st != SDC_OK)
        return st;
    CHECK_FIXED(pk, pk_len, ai->pk_len);
    if (!ct_len || !ss_len)
        return SDC_ERR_INVALID_ARG;
    if (*ct_len < ai->ct_len || *ss_len < ai->ss_len) {
        *ct_len = ai->ct_len;
        *ss_len = ai->ss_len;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    if (!ct || !ss)
        return SDC_ERR_INVALID_ARG;
    st = p->kem_encaps(alg, pk, ct, ss);
    if (st == SDC_OK) {
        *ct_len = ai->ct_len;
        *ss_len = ai->ss_len;
    } else {
        sdc_memzero(ss, ai->ss_len);
    }
    return st;
}

sdc_status sdc_kem_decaps(const sdc_ctx *ctx, sdc_alg alg,
                          const uint8_t *sk, size_t sk_len,
                          const uint8_t *ct, size_t ct_len,
                          uint8_t *ss, size_t *ss_len)
{
    const sdc_alg_info *ai;
    const sdc_provider *p;
    sdc_status st = prepare(ctx, alg, SDC_FAMILY_KEM, OP(kem_decaps), &ai, &p);
    if (st != SDC_OK)
        return st;
    CHECK_FIXED(sk, sk_len, ai->sk_len);
    CHECK_FIXED(ct, ct_len, ai->ct_len);
    CHECK_OUT(ss, ss_len, ai->ss_len);
    st = p->kem_decaps(alg, sk, ct, ss);
    if (st == SDC_OK)
        *ss_len = ai->ss_len;
    else
        sdc_memzero(ss, ai->ss_len);
    return st;
}

sdc_status sdc_kex_keypair(const sdc_ctx *ctx, sdc_alg alg,
                           uint8_t *pk, size_t *pk_len,
                           uint8_t *sk, size_t *sk_len)
{
    return keypair(ctx, alg, SDC_FAMILY_KEX, pk, pk_len, sk, sk_len);
}

sdc_status sdc_kex_derive(const sdc_ctx *ctx, sdc_alg alg,
                          const uint8_t *sk, size_t sk_len,
                          const uint8_t *peer_pk, size_t peer_pk_len,
                          uint8_t *ss, size_t *ss_len)
{
    static const uint8_t zero[64];
    const sdc_alg_info *ai;
    const sdc_provider *p;
    sdc_status st = prepare(ctx, alg, SDC_FAMILY_KEX, OP(kex_derive), &ai, &p);
    if (st != SDC_OK)
        return st;
    CHECK_FIXED(sk, sk_len, ai->sk_len);
    CHECK_FIXED(peer_pk, peer_pk_len, ai->pk_len);
    CHECK_OUT(ss, ss_len, ai->ss_len);
    st = p->kex_derive(alg, sk, peer_pk, ss);
    /* Defence in depth: never hand out an all-zero secret. */
    if (st == SDC_OK && sdc_ct_equal(ss, zero, ai->ss_len))
        st = SDC_ERR_INVALID_ARG;
    if (st == SDC_OK)
        *ss_len = ai->ss_len;
    else
        sdc_memzero(ss, ai->ss_len);
    return st;
}
