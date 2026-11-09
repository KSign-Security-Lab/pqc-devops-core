/* sdc_providers: print which provider serves each algorithm.
 *
 *   sdc_providers            matrix of every compiled-in provider
 *   SDC_PROVIDER=nettle sdc_providers
 *
 * SPDX-License-Identifier: Apache-2.0 */
#include "common.h"

int main(void)
{
    sdc_ctx *ctx;
    must(sdc_ctx_new(&ctx, NULL), "sdc_ctx_new");

    size_t np = sdc_provider_count();
    printf("sdc %s, %zu provider(s)\n\n%-20s %-6s", sdc_version(), np, "algorithm", "family");
    for (size_t p = 0; p < np; p++)
        printf(" %-8s", sdc_provider_name(p));
    printf(" %s\n", "selected");

    sdc_alg algs[64];
    size_t n = sdc_alg_list(SDC_FAMILY_NONE, algs, 64);
    for (size_t i = 0; i < n && i < 64; i++) {
        sdc_alg_info ai;
        sdc_alg_get_info(algs[i], &ai);
        printf("%-20s %-6s", ai.name, sdc_family_name(ai.family));
        for (size_t p = 0; p < np; p++)
            printf(" %-8s", sdc_provider_supports(sdc_provider_name(p), algs[i]) ? "yes" : "-");
        const char *sel = sdc_ctx_provider_for(ctx, algs[i]);
        printf(" %s\n", sel ? sel : "(none)");
    }
    sdc_ctx_free(ctx);
    sdc_cleanup();
    return 0;
}
