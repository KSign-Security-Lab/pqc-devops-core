/* sdc_seal: encrypt a file to a recipient's public key (KEM + HKDF + AEAD).
 *
 *   sdc_seal keygen [-a KEM] PK SK     default KEM: X25519-ML-KEM-768
 *   sdc_seal seal PK IN OUT
 *   sdc_seal open SK IN OUT
 *
 * Key files are: alg id (1 byte) || raw key. Sealed files are:
 *   "SDCS" | ver(1) | kem id(1) | kem ciphertext | AES-256-GCM(ct || tag)
 * The AEAD key is HKDF-SHA256(shared secret, info = "sdc_seal v1"), used
 * once, so a fixed zero nonce is safe. The header is authenticated as AAD.
 * SPDX-License-Identifier: Apache-2.0 */
#include "common.h"

static uint8_t *read_key(const char *path, size_t *len, sdc_alg *alg, int secret)
{
    sdc_alg_info ai;
    uint8_t *k = read_file(path, len);
    if (*len < 1 || sdc_alg_get_info((sdc_alg)k[0], &ai) != SDC_OK ||
        ai.family != SDC_FAMILY_KEM || *len - 1 != (secret ? ai.sk_len : ai.pk_len))
        die("%s: not a %s key file", path, secret ? "secret" : "public");
    *alg = ai.alg;
    *len -= 1;
    return k;
}

static void keygen(const sdc_ctx *ctx, sdc_alg kem, const char *pk_path, const char *sk_path)
{
    sdc_alg_info ai;
    sdc_alg_get_info(kem, &ai);
    uint8_t *pk = xmalloc(1 + ai.pk_len), *sk = xmalloc(1 + ai.sk_len);
    size_t pl = ai.pk_len, sl = ai.sk_len;
    pk[0] = sk[0] = (uint8_t)kem;
    must(sdc_kem_keypair(ctx, kem, pk + 1, &pl, sk + 1, &sl), "sdc_kem_keypair");
    write_file(pk_path, pk, 1 + pl);
    write_file(sk_path, sk, 1 + sl);
    fprintf(stderr, "generated %s key pair via %s\n", ai.name, sdc_ctx_provider_for(ctx, kem));
    sdc_memzero(sk, 1 + sl);
    free(pk);
    free(sk);
}

#define HDR 6
static const uint8_t INFO[] = "sdc_seal v1";
static const uint8_t ZERO_NONCE[12];

static void aead_key(const sdc_ctx *ctx, const uint8_t *ss, size_t ss_len, uint8_t key[32])
{
    must(sdc_hkdf(ctx, SDC_ALG_HKDF_SHA256, ss, ss_len, NULL, 0, INFO, sizeof INFO - 1,
                  key, 32), "sdc_hkdf");
}

static void seal(const sdc_ctx *ctx, const char *pk_path, const char *in, const char *out)
{
    sdc_alg kem;
    sdc_alg_info ai;
    size_t pkl, pl;
    uint8_t *pk = read_key(pk_path, &pkl, &kem, 0), *pt = read_file(in, &pl);
    sdc_alg_get_info(kem, &ai);
    size_t total = HDR + ai.ct_len + pl + 16, cl = ai.ct_len, sl = 32, ol = pl + 16;
    uint8_t *buf = xmalloc(total), ss[32], key[32];

    memcpy(buf, "SDCS", 4);
    buf[4] = 1;
    buf[5] = (uint8_t)kem;
    must(sdc_kem_encaps(ctx, kem, pk + 1, pkl, buf + HDR, &cl, ss, &sl), "sdc_kem_encaps");
    aead_key(ctx, ss, sl, key);
    must(sdc_aead_encrypt(ctx, SDC_ALG_AES_256_GCM, key, 32, ZERO_NONCE, 12,
                          buf, HDR + cl, pt, pl, buf + HDR + cl, &ol), "sdc_aead_encrypt");
    write_file(out, buf, HDR + cl + ol);
    sdc_memzero(ss, sizeof ss);
    sdc_memzero(key, sizeof key);
    free(pk); free(pt); free(buf);
}

static void open_sealed(const sdc_ctx *ctx, const char *sk_path, const char *in, const char *out)
{
    sdc_alg kem;
    sdc_alg_info ai;
    size_t skl, cl;
    uint8_t *sk = read_key(sk_path, &skl, &kem, 1), *ct = read_file(in, &cl);
    sdc_alg_get_info(kem, &ai);
    if (cl < HDR + ai.ct_len + 16 || memcmp(ct, "SDCS", 4) != 0 || ct[4] != 1)
        die("%s: not an sdc_seal v1 file", in);
    if (ct[5] != (uint8_t)kem)
        die("%s: sealed with a different KEM than %s", in, ai.name);

    uint8_t ss[32], key[32];
    size_t sl = 32, pl = cl - HDR - ai.ct_len - 16;
    uint8_t *pt = xmalloc(pl);
    must(sdc_kem_decaps(ctx, kem, sk + 1, skl, ct + HDR, ai.ct_len, ss, &sl), "sdc_kem_decaps");
    aead_key(ctx, ss, sl, key);
    sdc_status st = sdc_aead_decrypt(ctx, SDC_ALG_AES_256_GCM, key, 32, ZERO_NONCE, 12,
                                     ct, HDR + ai.ct_len, ct + HDR + ai.ct_len,
                                     cl - HDR - ai.ct_len, pt, &pl);
    sdc_memzero(ss, sizeof ss);
    sdc_memzero(key, sizeof key);
    if (st == SDC_ERR_AUTH_FAILED)
        die("%s: wrong key or corrupted file", in);
    must(st, "sdc_aead_decrypt");
    write_file(out, pt, pl);
    sdc_memzero(sk, skl + 1);
    free(sk); free(ct); free(pt);
}

int main(int argc, char **argv)
{
    sdc_ctx *ctx;
    sdc_alg kem = SDC_ALG_X25519_ML_KEM_768;
    int i = 2;
    if (argc < 2)
        goto usage;
    if (i + 1 < argc && strcmp(argv[i], "-a") == 0) {
        kem = parse_alg(argv[i + 1], SDC_FAMILY_KEM);
        i += 2;
    }
    must(sdc_ctx_new(&ctx, NULL), "sdc_ctx_new");
    if (strcmp(argv[1], "keygen") == 0 && argc - i == 2)
        keygen(ctx, kem, argv[i], argv[i + 1]);
    else if (strcmp(argv[1], "seal") == 0 && argc - i == 3)
        seal(ctx, argv[i], argv[i + 1], argv[i + 2]);
    else if (strcmp(argv[1], "open") == 0 && argc - i == 3)
        open_sealed(ctx, argv[i], argv[i + 1], argv[i + 2]);
    else
        goto usage;
    sdc_ctx_free(ctx);
    sdc_cleanup();
    return 0;
usage:
    die("usage: %s keygen [-a KEM] PK SK\n"
        "       %s seal PK IN OUT\n"
        "       %s open SK IN OUT", argv[0], argv[0], argv[0]);
    return 1;
}
