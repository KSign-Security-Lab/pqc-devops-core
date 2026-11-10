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
