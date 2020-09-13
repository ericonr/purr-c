#include <stdio.h>
#include <string.h>

#include "purr.h"

int main()
{
    int rv = 0;

    {
        /* formats.c */
        uint8_t buf[] = {0x12, 0x02, 0x12, 0x4c, 0xa8};
        char *expected = "1202124ca8";
        char *result = print_hex(buf, sizeof buf, false);

        printf("print_hex(): ");
        if (strcmp(expected, result)) {
            puts("failure");
            printf("expected: %s\ngot: %s\n", expected, result);
            rv = 1;
        } else {
            puts("success");
        }
    }

    return rv;
}
