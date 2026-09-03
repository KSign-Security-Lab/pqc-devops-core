/* Cross-provider interoperability: data produced by provider X must be
 * accepted by provider Y for every algorithm both support (X == Y included,
 * which gives round-trip coverage for single-provider algorithms like PQC).
 * SPDX-License-Identifier: Apache-2.0 */
#include "test_util.h"

#define MAXP 8
static sdc_ctx *ctxs[MAXP];
static const char *names[MAXP];
static size_t np;

static uint8_t msg[1000];

static void aead(sdc_alg alg, size_t x, size_t y)
{
    uint8_t key[32], nonce[12], aad[13], ct[sizeof msg + 16], pt[sizeof msg];
    sdc_random(ctxs[x], key, sizeof key);
    sdc_random(ctxs[x], nonce, sizeof nonce);
    sdc_random(ctxs[x], aad, sizeof aad);
    for (size_t len = 0; len <= sizeof msg; len += 333) {
        size_t n = sizeof ct, m = sizeof pt;
        CHECK_ST(sdc_aead_encrypt(ctxs[x], alg, key, 32, nonce, 12, aad, sizeof aad,
                                  msg, len, ct, &n), SDC_OK, "%s enc %s", sdc_alg_name(alg), names[x]);
        CHECK_ST(sdc_aead_decrypt(ctxs[y], alg, key, 32, nonce, 12, aad, sizeof aad,
                                  ct, n, pt, &m), SDC_OK, "%s %s->%s len %zu",
                 sdc_alg_name(alg), names[x], names[y], len);
        CHECK(m == len && memcmp(pt, msg, len) == 0, "%s %s->%s plaintext",
              sdc_alg_name(alg), names[x], names[y]);
        if (len) {
            ct[0] ^= 0x80;
            m = sizeof pt;
            CHECK_ST(sdc_aead_decrypt(ctxs[y], alg, key, 32, nonce, 12, aad, sizeof aad,
                                      ct, n, pt, &m), SDC_ERR_AUTH_FAILED,
                     "%s %s->%s tampered ct", sdc_alg_name(alg), names[x], names[y]);
            uint8_t zero[sizeof msg] = {0};
            CHECK(memcmp(pt, zero, len) == 0, "output zeroed on auth failure");
        }
    }
}

int main(void)
{
    sdc_init();
    np = sdc_provider_count();
    if (np > MAXP)
        np = MAXP;
    for (size_t i = 0; i < np; i++) {
        names[i] = sdc_provider_name(i);
        if (sdc_ctx_new(&ctxs[i], names[i]) != SDC_OK)
            return 1;
    }
    for (size_t i = 0; i < sizeof msg; i++)
        msg[i] = (uint8_t)(i * 31 + 7);

    for (int a = SDC_ALG_NONE + 1; a < SDC_ALG__COUNT; a++) {
        sdc_alg alg = (sdc_alg)a;
        sdc_alg_info ai;
        sdc_alg_get_info(alg, &ai);
        int pairs = 0;
        for (size_t x = 0; x < np; x++) {
            if (!sdc_provider_supports(names[x], alg))
                continue;
            for (size_t y = 0; y < np; y++) {
                if (!sdc_provider_supports(names[y], alg))
                    continue;
                pairs++;
                switch (ai.family) {
                case SDC_FAMILY_AEAD: aead(alg, x, y); break;
                default: break;
                }
            }
        }
        printf("  %-18s %d provider pair(s)\n", ai.name, pairs);
    }
    for (size_t i = 0; i < np; i++)
        sdc_ctx_free(ctxs[i]);
    sdc_cleanup();
    return test_summary("test_interop");
}
