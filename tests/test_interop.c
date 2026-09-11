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

static void digest(sdc_alg alg, size_t x, size_t y)
{
    uint8_t a[64], b[64];
    size_t na = sizeof a, nb = sizeof b;
    sdc_hash(ctxs[x], alg, msg, sizeof msg, a, &na);
    sdc_hash(ctxs[y], alg, msg, sizeof msg, b, &nb);
    CHECK(na == nb && memcmp(a, b, na) == 0, "%s %s vs %s", sdc_alg_name(alg), names[x], names[y]);
}

static void kdf(sdc_alg alg, size_t x, size_t y)
{
    uint8_t a[300], b[300];
    CHECK_ST(sdc_hkdf(ctxs[x], alg, msg, 50, msg + 50, 20, msg + 70, 10, a, sizeof a), SDC_OK,
             "%s %s", sdc_alg_name(alg), names[x]);
    CHECK_ST(sdc_hkdf(ctxs[y], alg, msg, 50, msg + 50, 20, msg + 70, 10, b, sizeof b), SDC_OK,
             "%s %s", sdc_alg_name(alg), names[y]);
    CHECK(memcmp(a, b, sizeof a) == 0, "%s %s vs %s", sdc_alg_name(alg), names[x], names[y]);
}

static void sig(sdc_alg alg, size_t x, size_t y)
{
    sdc_alg_info ai;
    sdc_alg_get_info(alg, &ai);
    uint8_t *pk = malloc(ai.pk_len), *sk = malloc(ai.sk_len), *s = malloc(ai.sig_len);
    size_t pkl = ai.pk_len, skl = ai.sk_len, sl = ai.sig_len;

    CHECK_ST(sdc_sig_keypair(ctxs[x], alg, pk, &pkl, sk, &skl), SDC_OK,
             "%s keypair %s", sdc_alg_name(alg), names[x]);
    /* X's keys: sign with Y, verify with X (secret-key format interop) */
    CHECK_ST(sdc_sign(ctxs[y], alg, sk, skl, msg, sizeof msg, s, &sl), SDC_OK,
             "%s sign %s with %s key", sdc_alg_name(alg), names[y], names[x]);
    CHECK_ST(sdc_verify(ctxs[x], alg, pk, pkl, msg, sizeof msg, s, sl), SDC_OK,
             "%s %s verifies %s sig", sdc_alg_name(alg), names[x], names[y]);
    /* sign with X, verify with Y (public-key + signature format interop) */
    sl = ai.sig_len;
    CHECK_ST(sdc_sign(ctxs[x], alg, sk, skl, msg, sizeof msg, s, &sl), SDC_OK,
             "%s sign %s", sdc_alg_name(alg), names[x]);
    CHECK_ST(sdc_verify(ctxs[y], alg, pk, pkl, msg, sizeof msg, s, sl), SDC_OK,
             "%s %s verifies %s sig", sdc_alg_name(alg), names[y], names[x]);
    s[sl / 2] ^= 0x01;
    CHECK_ST(sdc_verify(ctxs[y], alg, pk, pkl, msg, sizeof msg, s, sl), SDC_ERR_VERIFY_FAILED,
             "%s %s tampered sig from %s", sdc_alg_name(alg), names[y], names[x]);
    free(pk); free(sk); free(s);
}

static void kem(sdc_alg alg, size_t x, size_t y)
{
    sdc_alg_info ai;
    sdc_alg_get_info(alg, &ai);
    uint8_t *pk = malloc(ai.pk_len), *sk = malloc(ai.sk_len), *ct = malloc(ai.ct_len);
    uint8_t ss1[64], ss2[64];
    size_t pkl = ai.pk_len, skl = ai.sk_len, cl = ai.ct_len, s1 = sizeof ss1, s2 = sizeof ss2;

    CHECK_ST(sdc_kem_keypair(ctxs[x], alg, pk, &pkl, sk, &skl), SDC_OK,
             "%s keypair %s", sdc_alg_name(alg), names[x]);
    CHECK_ST(sdc_kem_encaps(ctxs[y], alg, pk, pkl, ct, &cl, ss1, &s1), SDC_OK,
             "%s encaps %s", sdc_alg_name(alg), names[y]);
    CHECK_ST(sdc_kem_decaps(ctxs[x], alg, sk, skl, ct, cl, ss2, &s2), SDC_OK,
             "%s decaps %s", sdc_alg_name(alg), names[x]);
    CHECK(s1 == ai.ss_len && s2 == s1 && memcmp(ss1, ss2, s1) == 0,
          "%s shared secrets differ", sdc_alg_name(alg));
    /* implicit rejection: tampered ct -> different secret, no error */
    ct[0] ^= 1;
    s2 = sizeof ss2;
    CHECK_ST(sdc_kem_decaps(ctxs[x], alg, sk, skl, ct, cl, ss2, &s2), SDC_OK,
             "%s decaps tampered", sdc_alg_name(alg));
    CHECK(memcmp(ss1, ss2, s1) != 0, "%s tampered ct gave same secret", sdc_alg_name(alg));
    free(pk); free(sk); free(ct);
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
                case SDC_FAMILY_HASH: digest(alg, x, y); break;
                case SDC_FAMILY_KDF:  kdf(alg, x, y); break;
                case SDC_FAMILY_SIG:  sig(alg, x, y); break;
                case SDC_FAMILY_KEM:  kem(alg, x, y); break;
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
