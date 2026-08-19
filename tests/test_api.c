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

int main(void)
{
    CHECK_ST(sdc_init(), SDC_OK, "%s", "init");
    test_alg_table();
    sdc_cleanup();
    return test_summary("test_api");
}
