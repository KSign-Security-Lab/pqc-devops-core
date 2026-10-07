/* Known-answer tests, run against every provider that supports each algorithm.
 * SPDX-License-Identifier: Apache-2.0 */
#include "test_util.h"

/* ----------------------------------------------------------------- vectors */

typedef struct {
    sdc_alg alg;
    const char *src, *key, *nonce, *aad, *pt, *ct, *tag;
} aead_kat;

static const aead_kat AEAD[] = {
    /* McGrew & Viega GCM spec, Test Case 16 */
    { SDC_ALG_AES_256_GCM, "GCM TC16",
      "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
      "cafebabefacedbaddecaf888",
      "feedfacedeadbeeffeedfacedeadbeefabaddad2",
      "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
      "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
      "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
      "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
      "76fc6ece0f4e1768cddf8853bb2d551b" },
    /* GCM spec Test Case 13: empty plaintext, empty AAD */
    { SDC_ALG_AES_256_GCM, "GCM TC13",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "000000000000000000000000", "", "", "",
      "530f8afbc74536b9a963b4f1c4cb738b" },
    /* GCM spec Test Case 4 (AES-128, AAD, 60-byte plaintext) */
    { SDC_ALG_AES_128_GCM, "GCM TC4",
      "feffe9928665731c6d6a8f9467308308",
      "cafebabefacedbaddecaf888",
      "feedfacedeadbeeffeedfacedeadbeefabaddad2",
      "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
      "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
      "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
      "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
      "5bc94fbc3221a5db94fae95ae7121a47" },
    /* GCM spec Test Case 1 (AES-128, all empty) */
    { SDC_ALG_AES_128_GCM, "GCM TC1",
      "00000000000000000000000000000000",
      "000000000000000000000000", "", "", "",
      "58e2fccefa7e3061367f1d57a4e7455a" },
    /* RFC 8439 section 2.8.2 */
    { SDC_ALG_CHACHA20_POLY1305, "RFC8439 2.8.2",
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
      "070000004041424344454647",
      "50515253c0c1c2c3c4c5c6c7",
      "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
      "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
      "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
      "637265656e20776f756c642062652069742e",
      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
      "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
      "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
      "3ff4def08e4b7a9de576d26586cec64b6116",
      "1ae10b594f09e26a7e902ecbd0600691" },
};

typedef struct { sdc_alg alg; const char *msg, *digest; } hash_kat;

/* FIPS 180-4 / FIPS 202 examples, message "abc" (and "" for SHA-256) */
static const hash_kat HASH[] = {
    { SDC_ALG_SHA256, "616263",
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
    { SDC_ALG_SHA256, "",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
    { SDC_ALG_SHA384, "616263",
      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
      "8086072ba1e7cc2358baeca134c825a7" },
    { SDC_ALG_SHA512, "616263",
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
      "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
    { SDC_ALG_SHA3_256, "616263",
      "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532" },
    { SDC_ALG_SHA3_512, "616263",
      "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
      "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0" },
    /* FIPS 180-4 SHA-224(\"abc\") */
    { SDC_ALG_SHA224, "616263",
      "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
    /* FIPS 202 SHA3-384(abc) */
    { SDC_ALG_SHA3_384, "616263",
      "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25" },
};

typedef struct { sdc_alg alg; const char *src, *ikm, *salt, *info, *okm; } hkdf_kat;

static const hkdf_kat HKDF[] = {
    /* RFC 5869 A.1 */
    { SDC_ALG_HKDF_SHA256, "RFC5869 A.1",
      "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
      "000102030405060708090a0b0c",
      "f0f1f2f3f4f5f6f7f8f9",
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
      "34007208d5b887185865" },
    /* RFC 5869 A.3: empty salt and info */
    { SDC_ALG_HKDF_SHA256, "RFC5869 A.3",
      "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "",
      "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
      "9d201395faa4b61a96c8" },
};

typedef struct { sdc_alg alg; const char *src, *sk, *pk, *msg, *sig; } sig_kat;

static const sig_kat SIG[] = {
    /* RFC 8032 7.1 TEST 1 / TEST 2 (deterministic: sign and verify) */
    { SDC_ALG_ED25519, "RFC8032 T1",
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" },
    { SDC_ALG_ED25519, "RFC8032 T2",
      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00" },
    /* RFC 6979 A.2.5, P-256 / SHA-256, message "sample" (verify only:
     * providers may use randomised nonces) */
    { SDC_ALG_ECDSA_P256_SHA256, "RFC6979 A.2.5",
      "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
      "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
      "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
      "73616d706c65",
      "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
      "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8" },
};

/* ------------------------------------------------------------------ runner */

static uint8_t A[512], B[512], C[512], D[512], E[512], F[512], G[512];

static void run_aead(const sdc_ctx *ctx, const char *prov, const aead_kat *v)
{
    size_t kl = unhex(v->key, A, sizeof A), nl = unhex(v->nonce, B, sizeof B);
    size_t al = unhex(v->aad, C, sizeof C), pl = unhex(v->pt, D, sizeof D);
    size_t cl = unhex(v->ct, E, sizeof E);
    unhex(v->tag, E + cl, sizeof E - cl);
    size_t n = sizeof F;
    CHECK_ST(sdc_aead_encrypt(ctx, v->alg, A, kl, B, nl, C, al, D, pl, F, &n), SDC_OK,
             "%s %s encrypt", prov, v->src);
    CHECK(n == cl + 16 && memcmp(F, E, n) == 0, "%s %s ciphertext||tag mismatch", prov, v->src);

    n = sizeof G;
    CHECK_ST(sdc_aead_decrypt(ctx, v->alg, A, kl, B, nl, C, al, E, cl + 16, G, &n), SDC_OK,
             "%s %s decrypt", prov, v->src);
    CHECK(n == pl && memcmp(G, D, pl) == 0, "%s %s plaintext mismatch", prov, v->src);

    E[cl + 15] ^= 1; /* tamper tag */
    n = sizeof G;
    CHECK_ST(sdc_aead_decrypt(ctx, v->alg, A, kl, B, nl, C, al, E, cl + 16, G, &n),
             SDC_ERR_AUTH_FAILED, "%s %s tampered tag", prov, v->src);
}

static void run_hash(const sdc_ctx *ctx, const char *prov, const hash_kat *v)
{
    size_t ml = unhex(v->msg, A, sizeof A), dl = unhex(v->digest, B, sizeof B);
    size_t n = sizeof C;
    CHECK_ST(sdc_hash(ctx, v->alg, ml ? A : NULL, ml, C, &n), SDC_OK,
             "%s %s", prov, sdc_alg_name(v->alg));
    CHECK(n == dl && memcmp(B, C, dl) == 0, "%s %s(%s) digest mismatch",
          prov, sdc_alg_name(v->alg), v->msg);
}

static void run_hkdf(const sdc_ctx *ctx, const char *prov, const hkdf_kat *v)
{
    size_t il = unhex(v->ikm, A, sizeof A), sl = unhex(v->salt, B, sizeof B);
    size_t fl = unhex(v->info, C, sizeof C), ol = unhex(v->okm, D, sizeof D);
    CHECK_ST(sdc_hkdf(ctx, v->alg, A, il, sl ? B : NULL, sl, fl ? C : NULL, fl, E, ol),
             SDC_OK, "%s %s", prov, v->src);
    CHECK(memcmp(D, E, ol) == 0, "%s %s okm mismatch", prov, v->src);
}

static void run_sig(const sdc_ctx *ctx, const char *prov, const sig_kat *v)
{
    size_t skl = unhex(v->sk, A, sizeof A), pkl = unhex(v->pk, B, sizeof B);
    size_t ml = unhex(v->msg, C, sizeof C), gl = unhex(v->sig, D, sizeof D);

    CHECK_ST(sdc_verify(ctx, v->alg, B, pkl, C, ml, D, gl), SDC_OK,
             "%s %s verify known sig", prov, v->src);

    size_t n = sizeof E;
    CHECK_ST(sdc_sign(ctx, v->alg, A, skl, C, ml, E, &n), SDC_OK, "%s %s sign", prov, v->src);
    if (v->alg == SDC_ALG_ED25519)
        CHECK(n == gl && memcmp(D, E, gl) == 0, "%s %s signature mismatch", prov, v->src);
    CHECK_ST(sdc_verify(ctx, v->alg, B, pkl, C, ml, E, n), SDC_OK,
             "%s %s verify own sig", prov, v->src);

    D[gl - 1] ^= 1;
    CHECK_ST(sdc_verify(ctx, v->alg, B, pkl, C, ml, D, gl), SDC_ERR_VERIFY_FAILED,
             "%s %s tampered sig", prov, v->src);
    D[gl - 1] ^= 1;
    C[0] ^= 1;
    CHECK_ST(sdc_verify(ctx, v->alg, B, pkl, C, ml ? ml : 1, D, gl), SDC_ERR_VERIFY_FAILED,
             "%s %s tampered msg", prov, v->src);
}

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

int main(void)
{
    sdc_init();
    for (size_t p = 0; p < sdc_provider_count(); p++) {
        const char *prov = sdc_provider_name(p);
        sdc_ctx *ctx;
        if (sdc_ctx_new(&ctx, prov) != SDC_OK) {
            CHECK(0, "ctx for %s", prov);
            continue;
        }
        int ran = 0;
#define RUN(arr, fn)                                         \
        for (size_t i = 0; i < COUNT(arr); i++)              \
            if (sdc_provider_supports(prov, arr[i].alg)) {   \
                fn(ctx, prov, &arr[i]);                      \
                ran++;                                       \
            }
        RUN(AEAD, run_aead);
        RUN(HASH, run_hash);
        RUN(HKDF, run_hkdf);
        RUN(SIG, run_sig);
        printf("  %-8s ran %d vectors\n", prov, ran);
        sdc_ctx_free(ctx);
    }
    sdc_cleanup();
    return test_summary("test_kat");
}
