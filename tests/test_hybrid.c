/* Hybrid X25519-ML-KEM-768 tests. SPDX-License-Identifier: Apache-2.0 */
#include "test_util.h"

static const sdc_alg H = SDC_ALG_X25519_ML_KEM_768;

static void roundtrip(const sdc_ctx *ctx, const char *label)
{
    sdc_alg_info ai;
    sdc_alg_get_info(H, &ai);
    uint8_t pk[1216], sk[2464], ct[1120], s1[32], s2[32];
    size_t pl = sizeof pk, sl = sizeof sk, cl = sizeof ct, n1 = 32, n2 = 32;
    CHECK_ST(sdc_kem_keypair(ctx, H, pk, &pl, sk, &sl), SDC_OK, "%s keypair", label);
    CHECK(pl == ai.pk_len && sl == ai.sk_len, "%s sizes", label);
    CHECK_ST(sdc_kem_encaps(ctx, H, pk, pl, ct, &cl, s1, &n1), SDC_OK, "%s encaps", label);
    CHECK_ST(sdc_kem_decaps(ctx, H, sk, sl, ct, cl, s2, &n2), SDC_OK, "%s decaps", label);
    CHECK(memcmp(s1, s2, 32) == 0, "%s secrets match", label);

    /* tampering with either half must change the secret */
    ct[0] ^= 1; /* ML-KEM part: implicit rejection */
    n2 = 32;
    CHECK_ST(sdc_kem_decaps(ctx, H, sk, sl, ct, cl, s2, &n2), SDC_OK, "%s decaps ct_M", label);
    CHECK(memcmp(s1, s2, 32) != 0, "%s ML-KEM tamper detected", label);
    ct[0] ^= 1;
    ct[1088] ^= 1; /* X25519 ephemeral key */
    n2 = 32;
    sdc_status st = sdc_kem_decaps(ctx, H, sk, sl, ct, cl, s2, &n2);
    CHECK(st != SDC_OK || memcmp(s1, s2, 32) != 0, "%s X25519 tamper detected", label);
}

int main(void)
{
    sdc_init();
    if (!sdc_ctx_provider_for(NULL, H)) {
        printf("hybrid KEM unavailable in this build; skipping\n");
        return test_summary("test_hybrid");
    }
    CHECK(strcmp(sdc_ctx_provider_for(NULL, H), "core") == 0, "%s", "served by core");
    roundtrip(NULL, "default");

    /* each half may come from a different provider */
    for (size_t i = 0; i < sdc_provider_count(); i++) {
        const char *p = sdc_provider_name(i);
        if (!sdc_provider_supports(p, SDC_ALG_X25519))
            continue;
        char pref[64];
        sdc_ctx *c;
        snprintf(pref, sizeof pref, "liboqs,%s", p);
        if (sdc_ctx_new(&c, pref) == SDC_OK) {
            roundtrip(c, pref);
            sdc_ctx_free(c);
        }
    }

    sdc_ctx *pq_only;
    if (sdc_ctx_new(&pq_only, "liboqs") == SDC_OK) {
        uint8_t pk[1216], sk[2464];
        size_t pl = sizeof pk, sl = sizeof sk;
        CHECK(sdc_ctx_provider_for(pq_only, H) == NULL, "%s", "needs X25519 too");
        CHECK_ST(sdc_kem_keypair(pq_only, H, pk, &pl, sk, &sl), SDC_ERR_NO_PROVIDER,
                 "%s", "liboqs alone");
        sdc_ctx_free(pq_only);
    }
    sdc_cleanup();
    return test_summary("test_hybrid");
}
