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

