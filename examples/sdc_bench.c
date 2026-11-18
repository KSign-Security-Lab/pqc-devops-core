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

/* Public-key operations use a key pair prepared once per (provider, alg). */
static uint8_t pk[4896], sk[4896], sig[4627], ct[1568], ss[32];
static size_t pk_len, sk_len, sig_len, ct_len;
static const uint8_t msg[] = "benchmark message";

static int prepare_keys(const sdc_ctx *ctx, sdc_alg alg, sdc_family fam)
{
    pk_len = sizeof pk;
    sk_len = sizeof sk;
    if (fam == SDC_FAMILY_SIG) {
        sig_len = sizeof sig;
        return sdc_sig_keypair(ctx, alg, pk, &pk_len, sk, &sk_len) == SDC_OK &&
               sdc_sign(ctx, alg, sk, sk_len, msg, sizeof msg, sig, &sig_len) == SDC_OK;
    }
    size_t sl = sizeof ss;
    ct_len = sizeof ct;
    return sdc_kem_keypair(ctx, alg, pk, &pk_len, sk, &sk_len) == SDC_OK &&
           sdc_kem_encaps(ctx, alg, pk, pk_len, ct, &ct_len, ss, &sl) == SDC_OK;
}

static int op_sign(const sdc_ctx *ctx, sdc_alg alg)
{
    size_t n = sizeof sig;
    return sdc_sign(ctx, alg, sk, sk_len, msg, sizeof msg, sig, &n) == SDC_OK;
}

static int op_verify(const sdc_ctx *ctx, sdc_alg alg)
{
    return sdc_verify(ctx, alg, pk, pk_len, msg, sizeof msg, sig, sig_len) == SDC_OK;
}

static int op_encaps(const sdc_ctx *ctx, sdc_alg alg)
{
    uint8_t c[1568], s[32];
    size_t cl = sizeof c, sl = sizeof s;
    return sdc_kem_encaps(ctx, alg, pk, pk_len, c, &cl, s, &sl) == SDC_OK;
}

static int op_decaps(const sdc_ctx *ctx, sdc_alg alg)
{
    size_t sl = sizeof ss;
    return sdc_kem_decaps(ctx, alg, sk, sk_len, ct, ct_len, ss, &sl) == SDC_OK;
}

static void pk_table(void)
{
    static const struct { sdc_alg alg; const char *what; int (*op)(const sdc_ctx *, sdc_alg); } rows[] = {
        { SDC_ALG_ED25519,           "sign",   op_sign },
        { SDC_ALG_ED25519,           "verify", op_verify },
        { SDC_ALG_ECDSA_P256_SHA256, "sign",   op_sign },
        { SDC_ALG_ECDSA_P256_SHA256, "verify", op_verify },
        { SDC_ALG_ML_DSA_65,         "sign",   op_sign },
        { SDC_ALG_ML_DSA_65,         "verify", op_verify },
        { SDC_ALG_ML_KEM_768,        "encaps", op_encaps },
        { SDC_ALG_ML_KEM_768,        "decaps", op_decaps },
    };
    printf("\n%-20s", "ops/s");
    for (size_t p = 0; p < sdc_provider_count(); p++)
        printf(" %10s", sdc_provider_name(p));
    printf("\n");
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        sdc_alg_info ai;
        sdc_alg_get_info(rows[i].alg, &ai);
        char label[40];
        snprintf(label, sizeof label, "%s %s", ai.name, rows[i].what);
        printf("%-20.20s", label);
        for (size_t p = 0; p < sdc_provider_count(); p++) {
            sdc_ctx *ctx;
            const char *name = sdc_provider_name(p);
            if (!sdc_provider_supports(name, rows[i].alg) || sdc_ctx_new(&ctx, name) != SDC_OK) {
                printf(" %10s", "-");
                continue;
            }
            double r = prepare_keys(ctx, rows[i].alg, ai.family) ? rate(rows[i].op, ctx, rows[i].alg)
                                                                   : -1;
            if (r < 0)
                printf(" %10s", "error");
            else
                printf(" %10.0f", r);
            sdc_ctx_free(ctx);
        }
        printf("\n");
    }
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
    pk_table();
    sdc_cleanup();
    return 0;
}
