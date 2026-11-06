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

/* Read a whole file ("-" = stdin). Caller frees. */
static inline uint8_t *read_file(const char *path, size_t *len)
{
    FILE *f = strcmp(path, "-") == 0 ? stdin : fopen(path, "rb");
    if (!f)
        die("cannot open %s", path);
    size_t cap = 4096, n = 0;
    uint8_t *buf = xmalloc(cap);
    for (;;) {
        if (n == cap) {
            uint8_t *nb = realloc(buf, cap *= 2);
            if (!nb)
                die("out of memory");
            buf = nb;
        }
        size_t r = fread(buf + n, 1, cap - n, f);
        n += r;
        if (r == 0)
            break;
    }
    if (ferror(f))
        die("read error on %s", path);
    if (f != stdin)
        fclose(f);
    *len = n;
    return buf;
}

/* Write a whole file ("-" = stdout). */
static inline void write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = strcmp(path, "-") == 0 ? stdout : fopen(path, "wb");
    if (!f)
        die("cannot create %s", path);
    if (fwrite(buf, 1, len, f) != len || (f != stdout && fclose(f) != 0))
        die("write error on %s", path);
    if (f == stdout)
        fflush(f);
}

static inline void print_hex(FILE *out, const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        fprintf(out, "%02x", buf[i]);
}

/* Parse an algorithm name and check its family. */
static inline sdc_alg parse_alg(const char *name, sdc_family want)
{
    sdc_alg_info ai;
    sdc_alg a = sdc_alg_from_name(name);
    if (a == SDC_ALG_NONE || sdc_alg_get_info(a, &ai) != SDC_OK)
        die("unknown algorithm: %s", name);
    if (want != SDC_FAMILY_NONE && ai.family != want)
        die("%s is a %s algorithm, expected %s", name, sdc_family_name(ai.family),
            sdc_family_name(want));
    return a;
}

#endif
