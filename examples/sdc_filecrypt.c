/* sdc_filecrypt: password-based file encryption.
 *
 *   sdc_filecrypt enc [-a AEAD] [-i ITER] PASSWORD IN OUT
 *   sdc_filecrypt dec PASSWORD IN OUT
 *
 * Key = PBKDF2-HMAC-SHA256(password, random 16-byte salt, ITER), then AEAD
 * (AES-256-GCM by default). The whole header is authenticated as AAD.
 *
 *   "SDCF" | ver(1) | aead id(1) | iterations(4, BE) | salt(16) | nonce(12)
 *   | ciphertext || tag
 *
 * Demo only: passing a password on the command line exposes it to other
 * local users through the process list.
 * SPDX-License-Identifier: Apache-2.0 */
#include "common.h"

#define HDR_LEN 38
#define DEFAULT_ITER 600000u

static void derive_key(const sdc_ctx *ctx, const char *password, const uint8_t *salt,
                       uint32_t iter, uint8_t *key, size_t key_len)
{
    must(sdc_pbkdf2(ctx, SDC_ALG_PBKDF2_SHA256, (const uint8_t *)password,
                    strlen(password), salt, 16, iter, key, key_len), "sdc_pbkdf2");
}

static void encrypt_file(const sdc_ctx *ctx, sdc_alg aead, uint32_t iter,
                         const char *password, const char *in, const char *out)
{
    sdc_alg_info ai;
    sdc_alg_get_info(aead, &ai);
    size_t pl, ol;
    uint8_t *pt = read_file(in, &pl), key[32];
    uint8_t *buf = xmalloc(HDR_LEN + pl + ai.tag_len);

    memcpy(buf, "SDCF", 4);
    buf[4] = 1;
    buf[5] = (uint8_t)aead;
    buf[6] = (uint8_t)(iter >> 24); buf[7] = (uint8_t)(iter >> 16);
    buf[8] = (uint8_t)(iter >> 8);  buf[9] = (uint8_t)iter;
    must(sdc_random(ctx, buf + 10, 16 + 12), "sdc_random"); /* salt + nonce */

    derive_key(ctx, password, buf + 10, iter, key, ai.key_len);
    ol = pl + ai.tag_len;
    must(sdc_aead_encrypt(ctx, aead, key, ai.key_len, buf + 26, 12, buf, HDR_LEN,
                          pt, pl, buf + HDR_LEN, &ol), "sdc_aead_encrypt");
    write_file(out, buf, HDR_LEN + ol);
    fprintf(stderr, "encrypted %zu bytes with %s via %s\n", pl, ai.name,
            sdc_ctx_provider_for(ctx, aead));
    sdc_memzero(key, sizeof key);
    sdc_memzero(pt, pl);
    free(pt);
    free(buf);
}

int main(int argc, char **argv)
{
    sdc_alg aead = SDC_ALG_AES_256_GCM;
    uint32_t iter = DEFAULT_ITER;
    int i = 2;
    if (argc < 2)
        goto usage;
    while (i + 1 < argc && argv[i][0] == '-') {
        if (strcmp(argv[i], "-a") == 0)
            aead = parse_alg(argv[i + 1], SDC_FAMILY_AEAD);
        else if (strcmp(argv[i], "-i") == 0)
            iter = (uint32_t)strtoul(argv[i + 1], NULL, 10);
        else
            goto usage;
        i += 2;
    }
    if (argc - i != 3 || iter == 0)
        goto usage;

    sdc_ctx *ctx;
    must(sdc_ctx_new(&ctx, NULL), "sdc_ctx_new");
    if (strcmp(argv[1], "enc") == 0)
        encrypt_file(ctx, aead, iter, argv[i], argv[i + 1], argv[i + 2]);
    else
        goto usage;
    sdc_ctx_free(ctx);
    sdc_cleanup();
    return 0;
usage:
    die("usage: %s enc [-a AEAD] [-i ITER] PASSWORD IN OUT\n"
        "       %s dec PASSWORD IN OUT", argv[0], argv[0]);
    return 1;
}
