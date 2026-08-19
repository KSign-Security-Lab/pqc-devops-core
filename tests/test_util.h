/* Minimal test helpers. SPDX-License-Identifier: Apache-2.0 */
#ifndef SDC_TEST_UTIL_H
#define SDC_TEST_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sdc/sdc.h"

static int g_failures;
static int g_checks;

#define CHECK(cond, ...)                                                    \
    do {                                                                    \
        g_checks++;                                                         \
        if (!(cond)) {                                                      \
            g_failures++;                                                   \
            fprintf(stderr, "FAIL %s:%d: %s -- ", __FILE__, __LINE__, #cond); \
            fprintf(stderr, __VA_ARGS__);                                   \
            fputc('\n', stderr);                                            \
        }                                                                   \
    } while (0)

#define CHECK_ST(expr, want, ctxfmt, ...)                                   \
    do {                                                                    \
        sdc_status _st = (expr);                                            \
        CHECK(_st == (want), ctxfmt ": got %s, want %s", __VA_ARGS__,       \
              sdc_strerror(_st), sdc_strerror(want));                       \
    } while (0)

static inline size_t unhex(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = strlen(hex) / 2;
    if (n > cap) {
        fprintf(stderr, "unhex: buffer too small\n");
        exit(2);
    }
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return n;
}

static inline int test_summary(const char *name)
{
    printf("%s: %d checks, %d failures\n", name, g_checks, g_failures);
    return g_failures ? 1 : 0;
}

#endif
