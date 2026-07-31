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

