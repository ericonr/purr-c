#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "purr.h"

/*
 * Set print to true to print value, otherwise returns dynamic string with the number
 */
char *print_hex(const uint8_t *buf, int len, bool print)
{
    char *rv = NULL;

    if (print) {
        // just print number into stdin
        for (int i = 0; i < len; i++) {
            printf("%02x", buf[i]);
        }
    } else {
        // print number into new string
        // new string has to be big enough to fit the whole number
        // 2 chars for each byte + 1 byte for NULL
        rv = malloc(len * 2 + 1);
        if (rv == NULL) {
            perror("allocation failure");
            return rv;
        }

        char *pos = rv;
        for (int i = 0; i < len; i++) {
            // will add the null terminator in the last run
            sprintf(pos, "%02x", buf[i]);
            pos += 2;
        }
    }

    return rv;
}

// from https://lemire.me/blog/2019/04/17/parsing-short-hexadecimal-strings-efficiently/
static uint32_t convert_hex_char(uint8_t c) {
    return (c & 0xF) + 9 * (c >> 6);
}

static uint8_t assemble_u8(const char *cs)
{
    uint8_t rv = 0;
    for (int i = 0; i < 2; i++) {
        int index = !i;
        rv |= convert_hex_char(cs[i]) << (4 * index);
    }
    return rv;
}

int decode_hex(const char *s, uint8_t *output, int len)
{
    for (int i = 0; i < len; i++) {
        int j = i * 2;
        int k = j + 1;

        if (isxdigit(s[j]) && isxdigit(s[k])) {
            output[i] = assemble_u8(s + j);
        } else {
            return -1;
        }
    }

    return 0;
}
