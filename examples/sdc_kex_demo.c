/* sdc_kex_demo: Alice and Bob agree on a session key, each using a
 * different crypto library, to show that the encodings interoperate.
 *
 *   sdc_kex_demo [ALICE_PROVIDERS] [BOB_PROVIDERS]
 *   e.g. sdc_kex_demo openssl nettle
 *
 * Both run X25519 and, when available, ML-KEM-768 (Bob encapsulates to
 * Alice); the session key is HKDF-SHA256 over both secrets.
 * SPDX-License-Identifier: Apache-2.0 */
#include "common.h"

static void session_key(const sdc_ctx *ctx, const uint8_t *x, const uint8_t *m, int have_m,
                        uint8_t key[32])
{
    static const uint8_t info[] = "sdc_kex_demo session";
    uint8_t ikm[64];
    memcpy(ikm, x, 32);
    if (have_m)
        memcpy(ikm + 32, m, 32);
    must(sdc_hkdf(ctx, SDC_ALG_HKDF_SHA256, ikm, have_m ? 64 : 32, NULL, 0, info,
                  sizeof info - 1, key, 32), "sdc_hkdf");
    sdc_memzero(ikm, sizeof ikm);
}

int main(int argc, char **argv)
{
    sdc_ctx *alice, *bob;
    must(sdc_ctx_new(&alice, argc > 1 ? argv[1] : NULL), "alice context");
    must(sdc_ctx_new(&bob, argc > 2 ? argv[2] : NULL), "bob context");
    printf("alice: X25519 via %s, ML-KEM-768 via %s\n",
           sdc_ctx_provider_for(alice, SDC_ALG_X25519),
           sdc_ctx_provider_for(alice, SDC_ALG_ML_KEM_768) ? sdc_ctx_provider_for(alice, SDC_ALG_ML_KEM_768) : "-");
    printf("bob:   X25519 via %s, ML-KEM-768 via %s\n",
           sdc_ctx_provider_for(bob, SDC_ALG_X25519),
           sdc_ctx_provider_for(bob, SDC_ALG_ML_KEM_768) ? sdc_ctx_provider_for(bob, SDC_ALG_ML_KEM_768) : "-");

    /* X25519 */
    uint8_t apk[32], ask[32], bpk[32], bsk[32], ax[32], bx[32];
    size_t a = 32, b = 32, n = 32;
    must(sdc_kex_keypair(alice, SDC_ALG_X25519, apk, &a, ask, &b), "alice X25519 keypair");
    a = b = 32;
    must(sdc_kex_keypair(bob, SDC_ALG_X25519, bpk, &a, bsk, &b), "bob X25519 keypair");
    must(sdc_kex_derive(alice, SDC_ALG_X25519, ask, 32, bpk, 32, ax, &n), "alice derive");
    n = 32;
    must(sdc_kex_derive(bob, SDC_ALG_X25519, bsk, 32, apk, 32, bx, &n), "bob derive");

    /* ML-KEM-768, if both sides have it */
    int pq = sdc_ctx_provider_for(alice, SDC_ALG_ML_KEM_768) &&
             sdc_ctx_provider_for(bob, SDC_ALG_ML_KEM_768);
    static uint8_t mpk[1184], msk[2400], mct[1088];
    uint8_t am[32] = {0}, bm[32] = {0};
    if (pq) {
        size_t pl = sizeof mpk, sl = sizeof msk, cl = sizeof mct, s1 = 32, s2 = 32;
        must(sdc_kem_keypair(alice, SDC_ALG_ML_KEM_768, mpk, &pl, msk, &sl), "alice ML-KEM keypair");
        must(sdc_kem_encaps(bob, SDC_ALG_ML_KEM_768, mpk, pl, mct, &cl, bm, &s1), "bob encaps");
        must(sdc_kem_decaps(alice, SDC_ALG_ML_KEM_768, msk, sl, mct, cl, am, &s2), "alice decaps");
    }

    uint8_t ak[32], bk[32];
    session_key(alice, ax, am, pq, ak);
    session_key(bob, bx, bm, pq, bk);
    printf("alice key: "); print_hex(stdout, ak, 32); printf("\n");
    printf("bob key:   "); print_hex(stdout, bk, 32); printf("\n");
    int ok = sdc_ct_equal(ak, bk, 32);
    printf("%s (%s)\n", ok ? "keys match" : "KEYS DIFFER", pq ? "hybrid" : "classical only");

    sdc_memzero(ask, sizeof ask); sdc_memzero(bsk, sizeof bsk);
    sdc_memzero(msk, sizeof msk);
    sdc_ctx_free(alice);
    sdc_ctx_free(bob);
    sdc_cleanup();
    return ok ? 0 : 1;
}
