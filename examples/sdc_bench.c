/* sdc_bench: compare providers on the same operations.
 *
 *   sdc_bench [SECONDS_PER_TEST]     default 0.2
 *
 * Bulk algorithms report MiB/s over 64 KiB messages; public-key
 * algorithms report operations per second. Each provider is measured in
 * its own single-provider context.
 * SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 199309L
#include <time.h>

#include "common.h"

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static double budget = 0.2;
static uint8_t buf[65536], out[65536 + 64];

/* Run op() repeatedly for `budget` seconds; return iterations per second. */
static double rate(int (*op)(const sdc_ctx *, sdc_alg), const sdc_ctx *ctx, sdc_alg alg)
{
    long n = 0;
    double t0 = now(), t;
    do {
        if (!op(ctx, alg))
            return -1;
        n++;
    } while ((t = now() - t0) < budget);
    return n / t;
}

static int op_aead(const sdc_ctx *ctx, sdc_alg alg)
{
    static const uint8_t key[32], nonce[12];
    sdc_alg_info ai;
    sdc_alg_get_info(alg, &ai);
    size_t n = sizeof out;
    return sdc_aead_encrypt(ctx, alg, key, ai.key_len, nonce, 12, NULL, 0, buf, sizeof buf,
                            out, &n) == SDC_OK;
}

static int op_hash(const sdc_ctx *ctx, sdc_alg alg)
{
    size_t n = 64;
    return sdc_hash(ctx, alg, buf, sizeof buf, out, &n) == SDC_OK;
}

int main(int argc, char **argv)
{
    if (argc > 1)
        budget = atof(argv[1]) > 0 ? atof(argv[1]) : budget;
    static const sdc_alg bulk[] = { SDC_ALG_AES_256_GCM, SDC_ALG_CHACHA20_POLY1305,
                                    SDC_ALG_SHA256, SDC_ALG_SHA3_256 };
    printf("%-20s", "MiB/s");
    for (size_t p = 0; p < sdc_provider_count(); p++)
        printf(" %10s", sdc_provider_name(p));
    printf("\n");
    for (size_t i = 0; i < sizeof bulk / sizeof bulk[0]; i++) {
        sdc_alg_info ai;
        sdc_alg_get_info(bulk[i], &ai);
        printf("%-20s", ai.name);
        for (size_t p = 0; p < sdc_provider_count(); p++) {
            sdc_ctx *ctx;
            const char *name = sdc_provider_name(p);
            if (!sdc_provider_supports(name, bulk[i]) || sdc_ctx_new(&ctx, name) != SDC_OK) {
                printf(" %10s", "-");
                continue;
            }
            double r = rate(ai.family == SDC_FAMILY_AEAD ? op_aead : op_hash, ctx, bulk[i]);
            printf(" %10.1f", r * sizeof buf / (1024.0 * 1024.0));
            sdc_ctx_free(ctx);
        }
        printf("\n");
    }
    sdc_cleanup();
    return 0;
}
