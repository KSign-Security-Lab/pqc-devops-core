/* sdc_hashsum: sha256sum-style tool built on the incremental hash API.
 *
 *   sdc_hashsum [-a ALG] FILE...      ("-" reads stdin; default SHA-256)
 *
 * SPDX-License-Identifier: Apache-2.0 */
#include "common.h"

static void hash_stream(const sdc_ctx *ctx, sdc_alg alg, FILE *f, const char *name)
{
    sdc_hash_ctx *h;
    uint8_t buf[65536], digest[64];
    size_t n, dl = sizeof digest;
    must(sdc_hash_init(ctx, alg, &h), "sdc_hash_init");
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        must(sdc_hash_update(h, buf, n), "sdc_hash_update");
    if (ferror(f))
        die("read error on %s", name);
    must(sdc_hash_final(h, digest, &dl), "sdc_hash_final");
    sdc_hash_free(h);
    print_hex(stdout, digest, dl);
    printf("  %s\n", name);
}

int main(int argc, char **argv)
{
    sdc_alg alg = SDC_ALG_SHA256;
    int i = 1;
    if (i + 1 < argc && strcmp(argv[i], "-a") == 0) {
        alg = parse_alg(argv[i + 1], SDC_FAMILY_HASH);
        i += 2;
    }
    if (i >= argc)
        die("usage: %s [-a ALG] FILE...", argv[0]);

    sdc_ctx *ctx;
    must(sdc_ctx_new(&ctx, NULL), "sdc_ctx_new");
    for (; i < argc; i++) {
        FILE *f = strcmp(argv[i], "-") == 0 ? stdin : fopen(argv[i], "rb");
        if (!f)
            die("cannot open %s", argv[i]);
        hash_stream(ctx, alg, f, argv[i]);
        if (f != stdin)
            fclose(f);
    }
    sdc_ctx_free(ctx);
    sdc_cleanup();
    return 0;
}
