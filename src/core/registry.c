/* Compile-time provider registry. SPDX-License-Identifier: Apache-2.0 */
#include <pthread.h>
#include <string.h>

#include "internal/provider.h"

/* Default preference order. Mature general-purpose libraries first, liboqs
 * last since it only serves the PQC algorithms. */
static const sdc_provider *const g_all[] = {
#ifdef SDC_HAVE_OPENSSL
    &sdc_provider_openssl,
#endif
#ifdef SDC_HAVE_NETTLE
    &sdc_provider_nettle,
#endif
#ifdef SDC_HAVE_GCRYPT
    &sdc_provider_gcrypt,
#endif
#ifdef SDC_HAVE_LIBOQS
    &sdc_provider_liboqs,
#endif
    NULL
};
#define N_ALL (sizeof(g_all) / sizeof(g_all[0]) - 1)

