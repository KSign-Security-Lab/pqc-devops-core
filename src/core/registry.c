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

/* Providers whose init() succeeded, in default order. */
static const sdc_provider *g_active[N_ALL + 1];
static size_t g_active_n;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_initialised;

static void do_init(void)
{
    g_active_n = 0;
    for (size_t i = 0; i < N_ALL; i++) {
        if (!g_all[i]->init || g_all[i]->init() == SDC_OK)
            g_active[g_active_n++] = g_all[i];
    }
    g_initialised = 1;
}

sdc_status sdc_init(void)
{
    pthread_once(&g_once, do_init);
    pthread_mutex_lock(&g_lock);
    if (!g_initialised) /* re-init after sdc_cleanup() */
        do_init();
    pthread_mutex_unlock(&g_lock);
    return SDC_OK;
}

void sdc_cleanup(void)
{
    pthread_mutex_lock(&g_lock);
    if (g_initialised) {
        for (size_t i = 0; i < g_active_n; i++)
            if (g_active[i]->cleanup)
                g_active[i]->cleanup();
        g_active_n = 0;
        g_initialised = 0;
    }
    pthread_mutex_unlock(&g_lock);
}

size_t sdc__provider_count(void)
{
    sdc_init();
    return g_active_n;
}

const sdc_provider *sdc__provider_at(size_t i)
{
    sdc_init();
    return i < g_active_n ? g_active[i] : NULL;
}

const sdc_provider *sdc__provider_by_name(const char *name, size_t len)
{
    sdc_init();
    for (size_t i = 0; i < g_active_n; i++) {
        const char *pn = g_active[i]->name;
        if (strlen(pn) == len && strncmp(pn, name, len) == 0)
            return g_active[i];
    }
    return NULL;
}

