/* Encoding helpers. SPDX-License-Identifier: Apache-2.0 */
#include "internal/provider.h"

static const char HEX[] = "0123456789abcdef";

sdc_status sdc_hex_encode(const uint8_t *in, size_t in_len,
                          char *out, size_t *out_len)
{
    if ((!in && in_len) || !out_len || in_len > (SIZE_MAX - 1) / 2)
        return SDC_ERR_INVALID_ARG;
    size_t need = 2 * in_len + 1;
    if (*out_len < need) {
        *out_len = need;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    if (!out)
        return SDC_ERR_INVALID_ARG;
    for (size_t i = 0; i < in_len; i++) {
        out[2 * i]     = HEX[in[i] >> 4];
        out[2 * i + 1] = HEX[in[i] & 0x0f];
    }
    out[2 * in_len] = '\0';
    *out_len = 2 * in_len;
    return SDC_OK;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

sdc_status sdc_hex_decode(const char *in, size_t in_len,
                          uint8_t *out, size_t *out_len)
{
    if ((!in && in_len) || !out_len || (in_len & 1))
        return SDC_ERR_INVALID_ARG;
    size_t need = in_len / 2;
    if (*out_len < need) {
        *out_len = need;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    if (!out && need)
        return SDC_ERR_INVALID_ARG;
    for (size_t i = 0; i < need; i++) {
        int hi = hexval(in[2 * i]), lo = hexval(in[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return SDC_ERR_INVALID_ARG;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    *out_len = need;
    return SDC_OK;
}

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

sdc_status sdc_base64_encode(const uint8_t *in, size_t in_len,
                             char *out, size_t *out_len)
{
    if ((!in && in_len) || !out_len || in_len > (SIZE_MAX / 4) * 3 - 3)
        return SDC_ERR_INVALID_ARG;
    size_t enc = (in_len + 2) / 3 * 4;
    if (*out_len < enc + 1) {
        *out_len = enc + 1;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    if (!out)
        return SDC_ERR_INVALID_ARG;
    size_t o = 0, i = 0;
    for (; i + 3 <= in_len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8 | in[i + 2];
        out[o++] = B64[v >> 18];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = B64[(v >> 6) & 63];
        out[o++] = B64[v & 63];
    }
    if (i < in_len) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < in_len)
            v |= (uint32_t)in[i + 1] << 8;
        out[o++] = B64[v >> 18];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = i + 1 < in_len ? B64[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    *out_len = o;
    return SDC_OK;
}
