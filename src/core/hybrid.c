/* Hybrid KEM: X25519 + ML-KEM-768, composed from the public API so that
 * each half can be served by a different provider.
 *
 *   pk = pk_M (1184) || pk_X (32)
 *   sk = sk_M (2400) || sk_X (32) || pk_X (32)
 *   ct = ct_M (1088) || ct_X (32)          ct_X = ephemeral X25519 public key
 *   ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || LABEL)
 *
 * The combiner follows the X-Wing construction (draft-connolly-cfrg-xwing-kem)
 * but key formats and label differ, so it is NOT interoperable with X-Wing.
 * SPDX-License-Identifier: Apache-2.0 */
#include <string.h>

#include "internal/hybrid.h"

#define PK_M 1184
#define SK_M 2400
#define CT_M 1088
#define X_LEN 32
#define SS 32

static const uint8_t LABEL[] = "SDC-X25519-MLKEM768-v1";

static sdc_status combine(const sdc_ctx *ctx, const uint8_t *ss_m, const uint8_t *ss_x,
                          const uint8_t *ct_x, const uint8_t *pk_x, uint8_t *ss)
{
    uint8_t buf[SS + SS + X_LEN + X_LEN + sizeof(LABEL) - 1];
    size_t n = SS;
    memcpy(buf, ss_m, SS);
    memcpy(buf + SS, ss_x, SS);
    memcpy(buf + 2 * SS, ct_x, X_LEN);
    memcpy(buf + 2 * SS + X_LEN, pk_x, X_LEN);
    memcpy(buf + 2 * SS + 2 * X_LEN, LABEL, sizeof(LABEL) - 1);
    sdc_status st = sdc_hash(ctx, SDC_ALG_SHA3_256, buf, sizeof(buf), ss, &n);
    sdc_memzero(buf, sizeof(buf));
    return st;
}

sdc_status sdc__hybrid_keypair(const sdc_ctx *ctx, uint8_t *pk, uint8_t *sk)
{
    size_t pl = PK_M, sl = SK_M;
    sdc_status st = sdc_kem_keypair(ctx, SDC_ALG_ML_KEM_768, pk, &pl, sk, &sl);
    if (st != SDC_OK)
        return st;
    pl = sl = X_LEN;
    st = sdc_kex_keypair(ctx, SDC_ALG_X25519, pk + PK_M, &pl, sk + SK_M, &sl);
    if (st != SDC_OK)
        return st;
    memcpy(sk + SK_M + X_LEN, pk + PK_M, X_LEN);
    return SDC_OK;
}

sdc_status sdc__hybrid_encaps(const sdc_ctx *ctx, const uint8_t *pk,
                              uint8_t *ct, uint8_t *ss)
{
    uint8_t ss_m[SS], ss_x[SS], esk[X_LEN];
    size_t cl = CT_M, sl = SS, pl = X_LEN, el = X_LEN;
    sdc_status st = sdc_kem_encaps(ctx, SDC_ALG_ML_KEM_768, pk, PK_M, ct, &cl, ss_m, &sl);
    if (st == SDC_OK)
        st = sdc_kex_keypair(ctx, SDC_ALG_X25519, ct + CT_M, &pl, esk, &el);
    sl = SS;
    if (st == SDC_OK)
        st = sdc_kex_derive(ctx, SDC_ALG_X25519, esk, X_LEN, pk + PK_M, X_LEN, ss_x, &sl);
    if (st == SDC_OK)
        st = combine(ctx, ss_m, ss_x, ct + CT_M, pk + PK_M, ss);
    sdc_memzero(ss_m, sizeof(ss_m));
    sdc_memzero(ss_x, sizeof(ss_x));
    sdc_memzero(esk, sizeof(esk));
    return st;
}

sdc_status sdc__hybrid_decaps(const sdc_ctx *ctx, const uint8_t *sk,
                              const uint8_t *ct, uint8_t *ss)
{
    uint8_t ss_m[SS], ss_x[SS];
    size_t sl = SS;
    sdc_status st = sdc_kem_decaps(ctx, SDC_ALG_ML_KEM_768, sk, SK_M, ct, CT_M, ss_m, &sl);
    sl = SS;
    if (st == SDC_OK)
        st = sdc_kex_derive(ctx, SDC_ALG_X25519, sk + SK_M, X_LEN, ct + CT_M, X_LEN,
                            ss_x, &sl);
    if (st == SDC_OK)
        st = combine(ctx, ss_m, ss_x, ct + CT_M, sk + SK_M + X_LEN, ss);
    sdc_memzero(ss_m, sizeof(ss_m));
    sdc_memzero(ss_x, sizeof(ss_x));
    return st;
}

int sdc__hybrid_available(const sdc_ctx *ctx)
{
    return sdc_ctx_provider_for(ctx, SDC_ALG_ML_KEM_768) &&
           sdc_ctx_provider_for(ctx, SDC_ALG_X25519) &&
           sdc_ctx_provider_for(ctx, SDC_ALG_SHA3_256);
}
