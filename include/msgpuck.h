/*
 * rtpengine_tarantool/include/msgpuck.h
 * Lightweight MessagePack encoder and decoder header
 */

#ifndef MSGPUCK_H_INCLUDED
#define MSGPUCK_H_INCLUDED

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* MP Constants */
#define MP_FIXINT_MAX  127
#define MP_FIXMAP      0x80
#define MP_FIXARRAY    0x90
#define MP_FIXSTR      0xa0
#define MP_NIL         0xc0
#define MP_FALSE       0xc2
#define MP_TRUE        0xc3
#define MP_BIN8        0xc4
#define MP_BIN16       0xc5
#define MP_BIN32       0xc6
#define MP_UINT8       0xcc
#define MP_UINT16      0xcd
#define MP_UINT32      0xce
#define MP_UINT64      0xcf
#define MP_INT8        0xd0
#define MP_INT16       0xd1
#define MP_INT32       0xd2
#define MP_INT64       0xd3
#define MP_STR8        0xd9
#define MP_STR16       0xda
#define MP_STR32       0xdb
#define MP_ARRAY16     0xdc
#define MP_ARRAY32     0xdd
#define MP_MAP16       0xde
#define MP_MAP32       0xdf

static inline char *mp_encode_nil(char *data) {
    *data++ = (char)MP_NIL;
    return data;
}

static inline char *mp_encode_bool(char *data, bool val) {
    *data++ = val ? (char)MP_TRUE : (char)MP_FALSE;
    return data;
}

static inline char *mp_encode_uint(char *data, uint64_t num) {
    if (num <= 0x7f) {
        *data++ = (char)num;
    } else if (num <= 0xff) {
        *data++ = (char)MP_UINT8;
        *data++ = (char)num;
    } else if (num <= 0xffff) {
        *data++ = (char)MP_UINT16;
        *data++ = (char)(num >> 8);
        *data++ = (char)num;
    } else if (num <= 0xffffffff) {
        *data++ = (char)MP_UINT32;
        *data++ = (char)(num >> 24);
        *data++ = (char)(num >> 16);
        *data++ = (char)(num >> 8);
        *data++ = (char)num;
    } else {
        *data++ = (char)MP_UINT64;
        for (int i = 7; i >= 0; --i)
            *data++ = (char)(num >> (i * 8));
    }
    return data;
}

static inline char *mp_encode_str(char *data, const char *str, uint32_t len) {
    if (len <= 31) {
        *data++ = (char)(MP_FIXSTR | len);
    } else if (len <= 0xff) {
        *data++ = (char)MP_STR8;
        *data++ = (char)len;
    } else if (len <= 0xffff) {
        *data++ = (char)MP_STR16;
        *data++ = (char)(len >> 8);
        *data++ = (char)len;
    } else {
        *data++ = (char)MP_STR32;
        *data++ = (char)(len >> 24);
        *data++ = (char)(len >> 16);
        *data++ = (char)(len >> 8);
        *data++ = (char)len;
    }
    if (str && len > 0) {
        memcpy(data, str, len);
        data += len;
    }
    return data;
}

static inline char *mp_encode_array(char *data, uint32_t size) {
    if (size <= 15) {
        *data++ = (char)(MP_FIXARRAY | size);
    } else if (size <= 0xffff) {
        *data++ = (char)MP_ARRAY16;
        *data++ = (char)(size >> 8);
        *data++ = (char)size;
    } else {
        *data++ = (char)MP_ARRAY32;
        *data++ = (char)(size >> 24);
        *data++ = (char)(size >> 16);
        *data++ = (char)(size >> 8);
        *data++ = (char)size;
    }
    return data;
}

static inline char *mp_encode_map(char *data, uint32_t size) {
    if (size <= 15) {
        *data++ = (char)(MP_FIXMAP | size);
    } else if (size <= 0xffff) {
        *data++ = (char)MP_MAP16;
        *data++ = (char)(size >> 8);
        *data++ = (char)size;
    } else {
        *data++ = (char)MP_MAP32;
        *data++ = (char)(size >> 24);
        *data++ = (char)(size >> 16);
        *data++ = (char)(size >> 8);
        *data++ = (char)size;
    }
    return data;
}

#if defined(__cplusplus)
}
#endif

#endif /* MSGPUCK_H_INCLUDED */
