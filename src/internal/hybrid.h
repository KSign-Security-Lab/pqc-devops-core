/* Hybrid KEM composed in the core. Not installed.
 * Inputs are already length-checked by the caller.
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef SDC_INTERNAL_HYBRID_H
#define SDC_INTERNAL_HYBRID_H

#include "sdc/sdc.h"

int        sdc__hybrid_available(const sdc_ctx *ctx);
sdc_status sdc__hybrid_keypair(const sdc_ctx *ctx, uint8_t *pk, uint8_t *sk);
sdc_status sdc__hybrid_encaps(const sdc_ctx *ctx, const uint8_t *pk,
                              uint8_t *ct, uint8_t *ss);
sdc_status sdc__hybrid_decaps(const sdc_ctx *ctx, const uint8_t *sk,
                              const uint8_t *ct, uint8_t *ss);

#endif
