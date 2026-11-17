/* sdc_signtool: detached signatures for files.
 *
 *   sdc_signtool keygen [-a ALG] PK SK     default ALG: ML-DSA-65
 *   sdc_signtool sign SK FILE SIG
 *   sdc_signtool verify PK FILE SIG        exit 0 = valid, 2 = invalid
 *
 * Key and signature files are: alg id (1 byte) || raw bytes.
 * SPDX-License-Identifier: Apache-2.0 */
#include "common.h"

static uint8_t *read_tagged(const char *path, size_t *len, sdc_alg *alg)
{
    sdc_alg_info ai;
    uint8_t *b = read_file(path, len);
    if (*len < 1 || sdc_alg_get_info((sdc_alg)b[0], &ai) != SDC_OK ||
        ai.family != SDC_FAMILY_SIG)
        die("%s: not an sdc_signtool file", path);
    *alg = ai.alg;
    *len -= 1;
    return b;
}

static void keygen(const sdc_ctx *ctx, sdc_alg alg, const char *pk_path, const char *sk_path)
{
    sdc_alg_info ai;
    sdc_alg_get_info(alg, &ai);
    uint8_t *pk = xmalloc(1 + ai.pk_len), *sk = xmalloc(1 + ai.sk_len);
    size_t pl = ai.pk_len, sl = ai.sk_len;
    pk[0] = sk[0] = (uint8_t)alg;
    must(sdc_sig_keypair(ctx, alg, pk + 1, &pl, sk + 1, &sl), "sdc_sig_keypair");
    write_file(pk_path, pk, 1 + pl);
    write_file(sk_path, sk, 1 + sl);
    sdc_memzero(sk, 1 + sl);
    free(pk);
    free(sk);
}

int main(int argc, char **argv)
{
    sdc_ctx *ctx;
    sdc_alg alg = SDC_ALG_ML_DSA_65;
    int i = 2, rc = 0;
    if (argc < 2)
        goto usage;
    if (i + 1 < argc && strcmp(argv[i], "-a") == 0) {
        alg = parse_alg(argv[i + 1], SDC_FAMILY_SIG);
        i += 2;
    }
    must(sdc_ctx_new(&ctx, NULL), "sdc_ctx_new");
    if (strcmp(argv[1], "keygen") == 0 && argc - i == 2)
        keygen(ctx, alg, argv[i], argv[i + 1]);
    else
        goto usage;
    sdc_ctx_free(ctx);
    sdc_cleanup();
    return rc;
usage:
    die("usage: %s keygen [-a ALG] PK SK\n"
        "       %s sign SK FILE SIG\n"
        "       %s verify PK FILE SIG", argv[0], argv[0], argv[0]);
    return 1;
}
