/* Demo: the application code below names algorithms only, never a crypto
 * library. Run it with SDC_PROVIDER=openssl|nettle|gcrypt|liboqs (or a list
 * such as "liboqs,nettle") to switch backends without recompiling.
 *
 * Flow: ML-KEM-768 key exchange -> HKDF-SHA256 -> AES-256-GCM, then an
 * ML-DSA-65 / Ed25519 signature. Steps whose algorithm has no provider in the
 * current configuration are reported and skipped.
 * SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <string.h>

#include "sdc/sdc.h"

static int g_rc;

static int step(const sdc_ctx *ctx, sdc_alg alg, sdc_status st, const char *what)
{
    const char *p = sdc_ctx_provider_for(ctx, alg);
    if (st == SDC_ERR_NO_PROVIDER) {
        printf("  %-18s %-22s skipped (no provider)\n", sdc_alg_name(alg), what);
        return 0;
    }
    printf("  %-18s %-22s via %-8s %s\n", sdc_alg_name(alg), what, p ? p : "?",
           st == SDC_OK ? "ok" : sdc_strerror(st));
    if (st != SDC_OK)
        g_rc = 1;
    return st == SDC_OK;
}

int main(void)
{
    sdc_ctx *ctx;
    sdc_status st = sdc_ctx_new(&ctx, NULL);
    if (st != SDC_OK) {
        fprintf(stderr, "sdc_ctx_new: %s\n", sdc_strerror(st));
        return 1;
    }
    printf("sdc %s\n", sdc_version());

    /* 1. Establish a shared secret (fallback: random secret). */
    uint8_t pk[1184], sk[2400], ct[1088], ss[32], ss2[32];
    size_t pkl = sizeof pk, skl = sizeof sk, cl = sizeof ct, sl = sizeof ss, sl2 = sizeof ss2;
    sdc_alg kem = SDC_ALG_ML_KEM_768;
    if (step(ctx, kem, sdc_kem_keypair(ctx, kem, pk, &pkl, sk, &skl), "keypair") &&
        step(ctx, kem, sdc_kem_encaps(ctx, kem, pk, pkl, ct, &cl, ss, &sl), "encapsulate") &&
        step(ctx, kem, sdc_kem_decaps(ctx, kem, sk, skl, ct, cl, ss2, &sl2), "decapsulate")) {
        printf("  shared secrets %s\n", memcmp(ss, ss2, 32) == 0 ? "match" : "DIFFER");
    } else if (sdc_random(ctx, ss, sizeof ss) != SDC_OK) {
        fprintf(stderr, "no RNG available\n");
        return 1;
    }

    /* 2. Derive an AEAD key and encrypt/decrypt. */
    uint8_t key[32], nonce[12] = {0};
    static const uint8_t info[] = "sdc-demo aead key";
    static const uint8_t msg[] = "post-quantum migration without touching app code";
    if (!step(ctx, SDC_ALG_HKDF_SHA256,
              sdc_hkdf(ctx, SDC_ALG_HKDF_SHA256, ss, sizeof ss, NULL, 0, info,
                       sizeof info - 1, key, sizeof key), "derive key"))
        memcpy(key, ss, sizeof key);

    uint8_t box[sizeof msg + 16], out[sizeof msg];
    size_t bl = sizeof box, ol = sizeof out;
    sdc_alg aead = SDC_ALG_AES_256_GCM;
    if (step(ctx, aead, sdc_aead_encrypt(ctx, aead, key, 32, nonce, 12, NULL, 0, msg,
                                         sizeof msg, box, &bl), "encrypt") &&
        step(ctx, aead, sdc_aead_decrypt(ctx, aead, key, 32, nonce, 12, NULL, 0, box, bl,
                                         out, &ol), "decrypt"))
        printf("  decrypted: \"%s\"\n", (const char *)out);

    /* 3. Sign and verify with whichever signature scheme is available. */
    static const sdc_alg sigs[] = { SDC_ALG_ML_DSA_65, SDC_ALG_ED25519 };
    for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++) {
        uint8_t spk[1952], ssk[4032], sig[3309];
        size_t spl = sizeof spk, ssl = sizeof ssk, sgl = sizeof sig;
        sdc_alg a = sigs[i];
        if (step(ctx, a, sdc_sig_keypair(ctx, a, spk, &spl, ssk, &ssl), "keypair") &&
            step(ctx, a, sdc_sign(ctx, a, ssk, ssl, msg, sizeof msg, sig, &sgl), "sign"))
            step(ctx, a, sdc_verify(ctx, a, spk, spl, msg, sizeof msg, sig, sgl), "verify");
    }

    sdc_ctx_free(ctx);
    sdc_cleanup();
    return g_rc;
}
