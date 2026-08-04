/* Public API: contexts, validation and dispatch. SPDX-License-Identifier: Apache-2.0 */
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

static const sdc_provider *pick(const sdc_ctx *ctx, sdc_alg alg)
{
    sdc_ctx tmp;
    ctx = resolve_ctx(ctx, &tmp);
    for (size_t i = 0; i < ctx->n; i++)
        if (ctx->order[i]->supports(alg))
            return ctx->order[i];
    return NULL;
}

const char *sdc_ctx_provider_for(const sdc_ctx *ctx, sdc_alg alg)
{
    if (!sdc__alg_info(alg))
        return NULL;
    const sdc_provider *p = pick(ctx, alg);
    return p ? p->name : NULL;
}

/* --------------------------------------------------------------- validation */

/* Resolve alg info + provider for an operation of the given family. */
static sdc_status prepare(const sdc_ctx *ctx, sdc_alg alg, sdc_family fam,
                          const sdc_alg_info **ai, const sdc_provider **p)
{
    *ai = sdc__alg_info(alg);
    if (!*ai)
        return SDC_ERR_UNSUPPORTED;
    if ((*ai)->family != fam)
        return SDC_ERR_INVALID_ARG;
    *p = pick(ctx, alg);
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
        if (ctx->order[i]->random)
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
    sdc_status st = prepare(ctx, alg, SDC_FAMILY_AEAD, &ai, &p);
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
    sdc_status st = prepare(ctx, alg, SDC_FAMILY_AEAD, &ai, &p);
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

