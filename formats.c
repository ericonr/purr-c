#include <stdio.h>
#include <stdlib.h>

#include "purr.h"

/*
 * Set print to true to print value, otherwise returns dynamic string with the number
 */
char *print_hex(uint8_t *buf, int len, bool print)
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

// TODO:
// buffer to base64
// base64 to buffer
