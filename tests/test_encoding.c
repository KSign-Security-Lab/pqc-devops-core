/* Encoding helper tests. SPDX-License-Identifier: Apache-2.0 */
#include "test_util.h"

static void test_hex(void)
{
    const uint8_t in[] = {0x00, 0x01, 0xab, 0xff};
    char s[16];
    uint8_t b[8];
    size_t n = sizeof s;
    CHECK_ST(sdc_hex_encode(in, 4, s, &n), SDC_OK, "%s", "encode");
    CHECK(n == 8 && strcmp(s, "0001abff") == 0, "hex %s", s);
    n = 3;
    CHECK_ST(sdc_hex_encode(in, 4, s, &n), SDC_ERR_BUFFER_TOO_SMALL, "%s", "small");
    CHECK(n == 9, "need %zu", n);
    n = sizeof s;
    CHECK_ST(sdc_hex_encode(NULL, 0, s, &n), SDC_OK, "%s", "empty");
    CHECK(n == 0 && s[0] == 0, "%s", "empty string");

    n = sizeof b;
    CHECK_ST(sdc_hex_decode("0001ABff", 8, b, &n), SDC_OK, "%s", "decode");
    CHECK(n == 4 && memcmp(b, in, 4) == 0, "%s", "decoded bytes");
    n = sizeof b;
    CHECK_ST(sdc_hex_decode("abc", 3, b, &n), SDC_ERR_INVALID_ARG, "%s", "odd");
    CHECK_ST(sdc_hex_decode("zz", 2, b, &n), SDC_ERR_INVALID_ARG, "%s", "non-hex");
    n = 1;
    CHECK_ST(sdc_hex_decode("0001", 4, b, &n), SDC_ERR_BUFFER_TOO_SMALL, "%s", "small");
    CHECK(n == 2, "need %zu", n);
}

static void test_base64(void)
{
    /* RFC 4648 section 10 */
    static const char *const v[][2] = {
        {"", ""}, {"f", "Zg=="}, {"fo", "Zm8="}, {"foo", "Zm9v"},
        {"foob", "Zm9vYg=="}, {"fooba", "Zm9vYmE="}, {"foobar", "Zm9vYmFy"},
    };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        char s[16];
        uint8_t b[16];
        size_t n = sizeof s, m = sizeof b, l = strlen(v[i][0]);
        CHECK_ST(sdc_base64_encode((const uint8_t *)v[i][0], l, s, &n), SDC_OK, "enc %s", v[i][0]);
        CHECK(strcmp(s, v[i][1]) == 0, "enc %s -> %s", v[i][0], s);
        CHECK_ST(sdc_base64_decode(v[i][1], strlen(v[i][1]), b, &m), SDC_OK, "dec %s", v[i][1]);
        CHECK(m == l && memcmp(b, v[i][0], l) == 0, "dec %s", v[i][1]);
    }
    uint8_t b[16];
    size_t m = sizeof b;
    CHECK_ST(sdc_base64_decode("Zg=", 3, b, &m), SDC_ERR_INVALID_ARG, "%s", "bad length");
    CHECK_ST(sdc_base64_decode("Zh==", 4, b, &m), SDC_ERR_INVALID_ARG, "%s", "non-canonical");
    CHECK_ST(sdc_base64_decode("Zm9!", 4, b, &m), SDC_ERR_INVALID_ARG, "%s", "bad char");
    CHECK_ST(sdc_base64_decode("Zg==Zg==", 8, b, &m), SDC_ERR_INVALID_ARG, "%s", "pad mid-string");
}

static void test_ct_equal(void)
{
    uint8_t a[33], b[33];
    for (size_t i = 0; i < sizeof a; i++)
        a[i] = b[i] = (uint8_t)i;
    CHECK(sdc_ct_equal(a, b, sizeof a) == 1, "%s", "equal");
    CHECK(sdc_ct_equal(a, b, 0) == 1, "%s", "empty");
    for (size_t i = 0; i < sizeof a; i++) {
        b[i] ^= 0x80;
        CHECK(sdc_ct_equal(a, b, sizeof a) == 0, "differ at %zu", i);
        b[i] ^= 0x80;
    }
}

int main(void)
{
    test_hex();
    test_base64();
    test_ct_equal();
    return test_summary("test_encoding");
}
