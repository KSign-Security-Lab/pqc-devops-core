/* API contract tests: lookup, validation, provider selection.
 * SPDX-License-Identifier: Apache-2.0 */
#include "test_util.h"

static void test_alg_table(void)
{
    for (int a = SDC_ALG_NONE + 1; a < SDC_ALG__COUNT; a++) {
        sdc_alg_info ai;
        CHECK(sdc_alg_get_info((sdc_alg)a, &ai) == SDC_OK, "alg %d", a);
        CHECK(ai.alg == (sdc_alg)a, "alg id %d", a);
        CHECK(sdc_alg_from_name(ai.name) == (sdc_alg)a, "round-trip %s", ai.name);
    }
    CHECK(sdc_alg_from_name("ml-kem-768") == SDC_ALG_ML_KEM_768, "case-insensitive");
    CHECK(sdc_alg_from_name("nope") == SDC_ALG_NONE, "unknown name");
    CHECK(sdc_alg_from_name(NULL) == SDC_ALG_NONE, "NULL name");
    CHECK(sdc_alg_name(SDC_ALG__COUNT) == NULL, "out of range");
    sdc_alg_info ai;
    CHECK(sdc_alg_get_info(SDC_ALG_NONE, &ai) == SDC_ERR_UNSUPPORTED, "NONE");
}

static void test_enumeration(void)
{
    sdc_alg all[SDC_ALG__COUNT];
    size_t total = sdc_alg_list(SDC_FAMILY_NONE, NULL, 0);
    CHECK(total == SDC_ALG__COUNT - 1, "total %zu", total);
    CHECK(sdc_alg_list(SDC_FAMILY_NONE, all, SDC_ALG__COUNT) == total, "%s", "fill");
    size_t sum = 0;
    for (int f = SDC_FAMILY_AEAD; f <= SDC_FAMILY_PBKDF; f++) {
        sdc_alg buf[SDC_ALG__COUNT];
        size_t n = sdc_alg_list((sdc_family)f, buf, SDC_ALG__COUNT);
        CHECK(sdc_family_name((sdc_family)f) != NULL, "family %d named", f);
        for (size_t i = 0; i < n; i++) {
            sdc_alg_info ai;
            sdc_alg_get_info(buf[i], &ai);
            CHECK(ai.family == (sdc_family)f, "%s in %s", ai.name, sdc_family_name(f));
        }
        sum += n;
    }
    CHECK(sum == total, "families cover all algorithms (%zu/%zu)", sum, total);
    sdc_alg one;
    CHECK(sdc_alg_list(SDC_FAMILY_NONE, &one, 1) == total && one == SDC_ALG_NONE + 1,
          "%s", "truncated listing");
    CHECK(sdc_family_name(SDC_FAMILY_NONE) == NULL, "%s", "NONE has no name");
}

static void test_contexts(void)
{
    sdc_ctx *c = NULL;
    CHECK(sdc_provider_count() > 0, "at least one provider");
    for (size_t i = 0; i < sdc_provider_count(); i++)
        printf("  provider[%zu] = %s\n", i, sdc_provider_name(i));

    CHECK_ST(sdc_ctx_new(&c, "does-not-exist"), SDC_ERR_NO_PROVIDER, "%s", "bad name");
    CHECK(c == NULL, "ctx stays NULL on error");
    CHECK_ST(sdc_ctx_new(&c, " , "), SDC_ERR_INVALID_ARG, "%s", "empty list");
    CHECK_ST(sdc_ctx_new(NULL, NULL), SDC_ERR_INVALID_ARG, "%s", "NULL out");

    if (sdc_provider_count() >= 2) {
        char pref[64];
        const char *a = sdc_provider_name(0), *b = sdc_provider_name(1);
        snprintf(pref, sizeof pref, "%s, %s,%s", b, a, b);
        CHECK_ST(sdc_ctx_new(&c, pref), SDC_OK, "%s", pref);
        CHECK(sdc_ctx_provider_count(c) == 2, "duplicates removed: %zu",
              sdc_ctx_provider_count(c));
        CHECK(strcmp(sdc_ctx_provider_name(c, 0), b) == 0 &&
              strcmp(sdc_ctx_provider_name(c, 1), a) == 0, "%s", "order kept");
        CHECK(sdc_ctx_provider_name(c, 2) == NULL, "%s", "out of range");
        sdc_ctx_free(c);
    }
    CHECK(sdc_ctx_provider_count(NULL) == sdc_provider_count(), "%s", "default ctx");

    const char *first = sdc_provider_name(0);
    CHECK_ST(sdc_ctx_new(&c, first), SDC_OK, "%s", first);
    for (int a = SDC_ALG_NONE + 1; a < SDC_ALG__COUNT; a++) {
        const char *p = sdc_ctx_provider_for(c, (sdc_alg)a);
        if (sdc_provider_supports(first, (sdc_alg)a))
            CHECK(p && strcmp(p, first) == 0, "%s served by %s", sdc_alg_name(a), first);
        else
            CHECK(p == NULL, "%s should have no provider in single-provider ctx",
                  sdc_alg_name(a));
    }
    sdc_ctx_free(c);

    /* Default context: report what serves each algorithm. */
    for (int a = SDC_ALG_NONE + 1; a < SDC_ALG__COUNT; a++) {
        const char *p = sdc_ctx_provider_for(NULL, (sdc_alg)a);
        printf("  %-18s -> %s\n", sdc_alg_name(a), p ? p : "(none)");
    }
}

/* gcrypt implements Ed25519 but not public-key derivation: a context that
 * prefers gcrypt must fall through to the next provider for that one
 * operation only. */
static void test_per_operation_fallback(void)
{
    if (!sdc_provider_supports("gcrypt", SDC_ALG_ED25519) ||
        !sdc_provider_supports("nettle", SDC_ALG_ED25519))
        return;
    sdc_ctx *only, *both;
    uint8_t sk[32] = {1}, pk[32];
    size_t n = sizeof pk;
    CHECK_ST(sdc_ctx_new(&only, "gcrypt"), SDC_OK, "%s", "gcrypt ctx");
    CHECK_ST(sdc_ctx_new(&both, "gcrypt,nettle"), SDC_OK, "%s", "gcrypt,nettle ctx");
    CHECK_ST(sdc_sig_public_key(only, SDC_ALG_ED25519, sk, 32, pk, &n),
             SDC_ERR_NO_PROVIDER, "%s", "gcrypt alone cannot derive");
    n = sizeof pk;
    CHECK_ST(sdc_sig_public_key(both, SDC_ALG_ED25519, sk, 32, pk, &n), SDC_OK,
             "%s", "falls through to nettle");
    CHECK(strcmp(sdc_ctx_provider_for(both, SDC_ALG_ED25519), "gcrypt") == 0,
          "%s", "gcrypt still preferred for the algorithm");
    sdc_ctx_free(only);
    sdc_ctx_free(both);
}

static void test_pqc_negative(void)
{
    if (!sdc_ctx_provider_for(NULL, SDC_ALG_ML_DSA_44) ||
        !sdc_ctx_provider_for(NULL, SDC_ALG_ML_KEM_512))
        return;
    static uint8_t pk[1312], sk[2560], sig[2420], ct[768], ss[32];
    static const uint8_t m[] = "message";
    size_t pl = sizeof pk, sl = sizeof sk, gl = sizeof sig, cl = sizeof ct, n = 32;

    CHECK_ST(sdc_sig_keypair(NULL, SDC_ALG_ML_DSA_44, pk, &pl, sk, &sl), SDC_OK, "%s", "ML-DSA kp");
    CHECK_ST(sdc_sign(NULL, SDC_ALG_ML_DSA_44, sk, sl - 1, m, sizeof m, sig, &gl),
             SDC_ERR_INVALID_ARG, "%s", "short ML-DSA sk");
    gl = sizeof sig;
    CHECK_ST(sdc_sign(NULL, SDC_ALG_ML_DSA_44, sk, sl, m, sizeof m, sig, &gl), SDC_OK, "%s", "sign");
    CHECK_ST(sdc_verify(NULL, SDC_ALG_ML_DSA_44, pk, pl, m, sizeof m, sig, gl - 1),
             SDC_ERR_VERIFY_FAILED, "%s", "truncated ML-DSA sig");
    CHECK_ST(sdc_verify(NULL, SDC_ALG_ML_DSA_44, pk, pl, m, sizeof m - 1, sig, gl),
             SDC_ERR_VERIFY_FAILED, "%s", "different message");
    CHECK_ST(sdc_verify(NULL, SDC_ALG_ML_DSA_44, pk, pl - 1, m, sizeof m, sig, gl),
             SDC_ERR_INVALID_ARG, "%s", "short ML-DSA pk");

    pl = 800, sl = 1632;
    CHECK_ST(sdc_kem_keypair(NULL, SDC_ALG_ML_KEM_512, pk, &pl, sk, &sl), SDC_OK, "%s", "ML-KEM kp");
    CHECK_ST(sdc_kem_encaps(NULL, SDC_ALG_ML_KEM_512, pk, pl, ct, &cl, ss, &n), SDC_OK, "%s", "enc");
    n = 32;
    CHECK_ST(sdc_kem_decaps(NULL, SDC_ALG_ML_KEM_512, sk, sl, ct, cl - 1, ss, &n),
             SDC_ERR_INVALID_ARG, "%s", "short ML-KEM ct");
    cl = 10;
    n = 32;
    CHECK_ST(sdc_kem_encaps(NULL, SDC_ALG_ML_KEM_512, pk, pl, ct, &cl, ss, &n),
             SDC_ERR_BUFFER_TOO_SMALL, "%s", "small ct buffer");
    CHECK(cl == 768, "required ct size %zu", cl);
}

static void test_validation(void)
{
    uint8_t key[32] = {0}, nonce[12] = {0}, buf[64], pt[4] = {1, 2, 3, 4};
    size_t n;
    sdc_alg aead = SDC_ALG_AES_256_GCM;

    if (!sdc_ctx_provider_for(NULL, aead))
        return;

    n = sizeof(buf);
    CHECK_ST(sdc_aead_encrypt(NULL, aead, key, 16, nonce, 12, NULL, 0, pt, 4, buf, &n),
             SDC_ERR_INVALID_ARG, "%s", "short key");
    CHECK_ST(sdc_aead_encrypt(NULL, aead, key, 32, nonce, 8, NULL, 0, pt, 4, buf, &n),
             SDC_ERR_INVALID_ARG, "%s", "short nonce");
    CHECK_ST(sdc_aead_encrypt(NULL, aead, key, 32, nonce, 12, NULL, 5, pt, 4, buf, &n),
             SDC_ERR_INVALID_ARG, "%s", "NULL aad with length");
    n = 10;
    CHECK_ST(sdc_aead_encrypt(NULL, aead, key, 32, nonce, 12, NULL, 0, pt, 4, buf, &n),
             SDC_ERR_BUFFER_TOO_SMALL, "%s", "small out");
    CHECK(n == 20, "required size reported: %zu", n);
    CHECK_ST(sdc_aead_encrypt(NULL, SDC_ALG_SHA256, key, 32, nonce, 12, NULL, 0, pt, 4, buf, &n),
             SDC_ERR_INVALID_ARG, "%s", "wrong family");
    CHECK_ST(sdc_aead_encrypt(NULL, (sdc_alg)999, key, 32, nonce, 12, NULL, 0, pt, 4, buf, &n),
             SDC_ERR_UNSUPPORTED, "%s", "unknown alg");
    n = sizeof(buf);
    CHECK_ST(sdc_aead_decrypt(NULL, aead, key, 32, nonce, 12, NULL, 0, buf, 8, buf, &n),
             SDC_ERR_INVALID_ARG, "%s", "input shorter than tag");

    n = 4;
    CHECK_ST(sdc_hash(NULL, SDC_ALG_SHA256, pt, 4, buf, &n), SDC_ERR_BUFFER_TOO_SMALL,
             "%s", "hash small");
    CHECK(n == 32, "hash size %zu", n);

    if (sdc_ctx_provider_for(NULL, SDC_ALG_HKDF_SHA256)) {
        CHECK_ST(sdc_hkdf(NULL, SDC_ALG_HKDF_SHA256, pt, 4, NULL, 0, NULL, 0, buf, 0),
                 SDC_ERR_INVALID_ARG, "%s", "hkdf len 0");
        CHECK_ST(sdc_hkdf(NULL, SDC_ALG_HKDF_SHA256, pt, 4, NULL, 0, NULL, 0, buf, 255 * 32 + 1),
                 SDC_ERR_INVALID_ARG, "%s", "hkdf too long");
    } else {
        CHECK_ST(sdc_hkdf(NULL, SDC_ALG_HKDF_SHA256, pt, 4, NULL, 0, NULL, 0, buf, 32),
                 SDC_ERR_NO_PROVIDER, "%s", "hkdf without provider");
    }

    if (sdc_ctx_provider_for(NULL, SDC_ALG_PBKDF2_SHA256)) {
        CHECK_ST(sdc_pbkdf2(NULL, SDC_ALG_PBKDF2_SHA256, pt, 4, pt, 4, 0, buf, 32),
                 SDC_ERR_INVALID_ARG, "%s", "pbkdf2 zero iterations");
        CHECK_ST(sdc_pbkdf2(NULL, SDC_ALG_PBKDF2_SHA256, pt, 4, pt, 4, 1, buf, 0),
                 SDC_ERR_INVALID_ARG, "%s", "pbkdf2 empty output");
        CHECK_ST(sdc_pbkdf2(NULL, SDC_ALG_PBKDF2_SHA256, pt, 4, NULL, 0, 1, buf, 32),
                 SDC_ERR_INVALID_ARG, "%s", "pbkdf2 empty salt");
        CHECK_ST(sdc_pbkdf2(NULL, SDC_ALG_HKDF_SHA256, pt, 4, pt, 4, 1, buf, 32),
                 SDC_ERR_INVALID_ARG, "%s", "pbkdf2 with HKDF alg");
    }

    if (sdc_ctx_provider_for(NULL, SDC_ALG_ED25519)) {
        uint8_t pk[65], sk[32];
        size_t pkl = 10, skl = 10;
        CHECK_ST(sdc_sig_keypair(NULL, SDC_ALG_ED25519, pk, &pkl, sk, &skl),
                 SDC_ERR_BUFFER_TOO_SMALL, "%s", "keypair small");
        CHECK(pkl == 32 && skl == 32, "keypair sizes %zu %zu", pkl, skl);
    }

    CHECK_ST(sdc_random(NULL, buf, 0), SDC_OK, "%s", "random 0");
    CHECK_ST(sdc_random(NULL, buf, sizeof(buf)), SDC_OK, "%s", "random");
}

int main(void)
{
    CHECK_ST(sdc_init(), SDC_OK, "%s", "init");
    test_alg_table();
    test_enumeration();
    test_contexts();
    test_per_operation_fallback();
    test_validation();
    test_pqc_negative();
    sdc_cleanup();
    return test_summary("test_api");
}
