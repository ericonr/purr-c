#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "purr.h"

static int compare_strings(const char *expected, const char *result, const char *function)
{
    int rv = 0;

    printf("%s(): ", function);
    if (strcmp(expected, result)) {
        rv = 1;
        puts("failure");
        printf("expected: %s\ngot: %s\n", expected, result);
    } else {
        puts("success");
    }

    return rv;
}

int main()
{
    int rv = 0;

    {
        /* formats.c */
        uint8_t buf[] = {0x12, 0x02, 0x12, 0x4c, 0xa8};
        const char *expected = "1202124ca8";
        const char *result = print_hex(buf, sizeof buf, false);
        rv = compare_strings(expected, result, "print_hex") ? 1 : rv;
    }

    {
        /* urls.c */
        const char *dirty = "https://hello.com/ash";
        char clean[4096], path[4096], port[16];
        int portn = clean_up_link(dirty, clean, path, port);
        rv = compare_strings("hello.com", clean, "clean_up_link") ? 1 : rv;
        rv = compare_strings("/ash", path, "clean_up_link") ? 1 : rv;
        rv = compare_strings("443", port, "clean_up_link") ? 1 : rv;
        assert(portn == HTTPS_PORT);

        dirty = "http://hello.com";
        portn = clean_up_link(dirty, clean, path, port);
        rv = compare_strings("hello.com", clean, "clean_up_link") ? 1 : rv;
        rv = compare_strings("/", path, "clean_up_link") ? 1 : rv;
        rv = compare_strings("80", port, "clean_up_link") ? 1 : rv;
        assert(portn == HTTP_PORT);
    }

    return rv;
}
