/* Small helpers shared by the example programs. Not part of the SDK API.
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef SDC_EXAMPLES_COMMON_H
#define SDC_EXAMPLES_COMMON_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sdc/sdc.h"

static inline void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

/* Abort with a readable message if an SDK call failed. */
static inline void must(sdc_status st, const char *what)
{
    if (st != SDC_OK)
        die("%s: %s", what, sdc_strerror(st));
}

static inline void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p)
        die("out of memory");
    return p;
}

#endif
