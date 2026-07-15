/* SDC Crypto-Agility SDK public API.
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef SDC_SDC_H
#define SDC_SDC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#  define SDC_API
#else
#  define SDC_API __attribute__((visibility("default")))
#endif

#define SDC_VERSION_STRING "0.1.0"

/* ------------------------------------------------------------------ status */

typedef enum sdc_status {
    SDC_OK = 0,
    SDC_ERR_INVALID_ARG,      /* NULL pointer, wrong length, wrong alg family */
    SDC_ERR_UNSUPPORTED,      /* algorithm unknown to the SDK                  */
    SDC_ERR_BUFFER_TOO_SMALL, /* *out_len updated with the required size      */
    SDC_ERR_AUTH_FAILED,      /* AEAD tag mismatch                             */
    SDC_ERR_VERIFY_FAILED,    /* signature invalid                             */
    SDC_ERR_PROVIDER,         /* backend library reported an error             */
    SDC_ERR_NO_PROVIDER,      /* no enabled provider implements the algorithm  */
    SDC_ERR_NOMEM
} sdc_status;

SDC_API const char *sdc_strerror(sdc_status st);
SDC_API const char *sdc_version(void);


#ifdef __cplusplus
}
#endif
#endif /* SDC_SDC_H */
