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

int main(void)
{
    test_hex();
    return test_summary("test_encoding");
}
