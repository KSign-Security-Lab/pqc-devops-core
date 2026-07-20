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

/* -------------------------------------------------------------- algorithms */

typedef enum sdc_alg {
    SDC_ALG_NONE = 0,
    /* AEAD */
    SDC_ALG_AES_256_GCM,
    SDC_ALG_CHACHA20_POLY1305,
    /* Hash */
    SDC_ALG_SHA256,
    SDC_ALG_SHA384,
    SDC_ALG_SHA512,
    SDC_ALG_SHA3_256,
    SDC_ALG_SHA3_512,
    /* KDF */
    SDC_ALG_HKDF_SHA256,
    SDC_ALG_HKDF_SHA512,
    /* Signatures */
    SDC_ALG_ED25519,
    SDC_ALG_ECDSA_P256_SHA256,
    SDC_ALG_ML_DSA_44,
    SDC_ALG_ML_DSA_65,
    SDC_ALG_ML_DSA_87,
    /* KEM */
    SDC_ALG_ML_KEM_512,
    SDC_ALG_ML_KEM_768,
    SDC_ALG_ML_KEM_1024,
    SDC_ALG__COUNT
} sdc_alg;

typedef enum sdc_family {
    SDC_FAMILY_NONE = 0,
    SDC_FAMILY_AEAD,
    SDC_FAMILY_HASH,
    SDC_FAMILY_KDF,
    SDC_FAMILY_SIG,
    SDC_FAMILY_KEM
} sdc_family;

/* Fixed sizes of an algorithm, in bytes (0 = not applicable).
 * sig_len is the maximum signature size. */
typedef struct sdc_alg_info {
    sdc_alg     alg;
    const char *name;
    sdc_family  family;
    size_t key_len;     /* AEAD key                         */
    size_t nonce_len;   /* AEAD nonce                       */
    size_t tag_len;     /* AEAD tag                         */
    size_t digest_len;  /* hash output / KDF underlying hash */
    size_t pk_len;      /* public key                       */
    size_t sk_len;      /* secret key                       */
    size_t sig_len;     /* max signature                    */
    size_t ct_len;      /* KEM ciphertext                   */
    size_t ss_len;      /* KEM shared secret                */
} sdc_alg_info;


#ifdef __cplusplus
}
#endif
#endif /* SDC_SDC_H */
