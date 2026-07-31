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

