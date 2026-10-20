/*
 * Internal provider interface. Not installed.
 *
 * The core validates every argument (pointers, key/nonce/buffer lengths,
 * algorithm family) before calling a provider, so provider functions can
 * assume:
 *  - `alg` belongs to the right family and supports(alg) returned non-zero;
 *  - fixed-size inputs/outputs have exactly the length in sdc_alg_info;
 *  - variable-length inputs may be NULL only when their length is 0.
 *
 * A NULL function pointer means the provider does not implement that family.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SDC_INTERNAL_PROVIDER_H
#define SDC_INTERNAL_PROVIDER_H

#include "sdc/sdc.h"

typedef struct sdc_provider {
    const char *name;

    sdc_status (*init)(void);
    void       (*cleanup)(void);
    int        (*supports)(sdc_alg alg);

    sdc_status (*random)(uint8_t *buf, size_t len);

    /* ct and pt have pt_len bytes; tag has tag_len bytes. */
    sdc_status (*aead_encrypt)(sdc_alg alg, const uint8_t *key,
                               const uint8_t *nonce,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *pt, size_t pt_len,
                               uint8_t *ct, uint8_t *tag);
    /* Must return SDC_ERR_AUTH_FAILED on tag mismatch. */
    sdc_status (*aead_decrypt)(sdc_alg alg, const uint8_t *key,
                               const uint8_t *nonce,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *ct, size_t ct_len,
                               const uint8_t *tag, uint8_t *pt);

    /* out has digest_len bytes. */
    sdc_status (*hash)(sdc_alg alg, const uint8_t *in, size_t in_len,
                       uint8_t *out);

    sdc_status (*hkdf)(sdc_alg alg, const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len);

    /* out has digest_len bytes. */
    sdc_status (*mac)(sdc_alg alg, const uint8_t *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len, uint8_t *out);

    /* pk/sk have pk_len/sk_len bytes. */
    sdc_status (*sig_keypair)(sdc_alg alg, uint8_t *pk, uint8_t *sk);
    /* sig has sig_len (max) bytes; *sig_len receives the actual length. */
    sdc_status (*sign)(sdc_alg alg, const uint8_t *sk,
                       const uint8_t *msg, size_t msg_len,
                       uint8_t *sig, size_t *sig_len);
    /* Must return SDC_ERR_VERIFY_FAILED for an invalid signature. */
    sdc_status (*verify)(sdc_alg alg, const uint8_t *pk,
                         const uint8_t *msg, size_t msg_len,
                         const uint8_t *sig, size_t sig_len);

    sdc_status (*kem_keypair)(sdc_alg alg, uint8_t *pk, uint8_t *sk);
    sdc_status (*kem_encaps)(sdc_alg alg, const uint8_t *pk,
                             uint8_t *ct, uint8_t *ss);
    sdc_status (*kem_decaps)(sdc_alg alg, const uint8_t *sk,
                             const uint8_t *ct, uint8_t *ss);

    sdc_status (*kex_keypair)(sdc_alg alg, uint8_t *pk, uint8_t *sk);
    /* Must return SDC_ERR_INVALID_ARG if the peer key is unusable. */
    sdc_status (*kex_derive)(sdc_alg alg, const uint8_t *sk,
                             const uint8_t *peer_pk, uint8_t *ss);
} sdc_provider;

/* Registry (src/core/registry.c) */
size_t              sdc__provider_count(void);
const sdc_provider *sdc__provider_at(size_t i);
const sdc_provider *sdc__provider_by_name(const char *name, size_t len);

/* Algorithm table (src/core/alg_table.c) */
const sdc_alg_info *sdc__alg_info(sdc_alg alg);

/* Compiled-in providers */
#ifdef SDC_HAVE_OPENSSL
extern const sdc_provider sdc_provider_openssl;
#endif
#ifdef SDC_HAVE_NETTLE
extern const sdc_provider sdc_provider_nettle;
#endif
#ifdef SDC_HAVE_GCRYPT
extern const sdc_provider sdc_provider_gcrypt;
#endif
#ifdef SDC_HAVE_LIBOQS
extern const sdc_provider sdc_provider_liboqs;
#endif

#endif /* SDC_INTERNAL_PROVIDER_H */
