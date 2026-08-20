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

int main(void)
{
    CHECK_ST(sdc_init(), SDC_OK, "%s", "init");
    test_alg_table();
    test_contexts();
    sdc_cleanup();
    return test_summary("test_api");
}
