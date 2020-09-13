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

static int compare_arrays(const uint8_t *expected, const uint8_t *result, size_t len, const char *function)
{
    int rv = 0;

    printf("%s(): ", function);
    if (memcmp(expected, result, len)) {
        rv = 1;
        puts("failure");
        printf("expected: %s\ngot: %s\n", print_hex(expected, len, false), print_hex(result, len, false));
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

        dirty = "https://bsd.ac/paste.html#sieqaqk_73fe_df51";
        portn = clean_up_link(dirty, clean, path, port);
        rv = compare_strings("bsd.ac", clean, "clean_up_link") ? 1 : rv;
        rv = compare_strings("/paste.html#sieqaqk_73fe_df51", path, "clean_up_link") ? 1 : rv;
        rv = compare_strings("443", port, "clean_up_link") ? 1 : rv;
        assert(portn == HTTPS_PORT);
        uint8_t key_exc[KEY_LEN] = {0x73, 0xfe};
        uint8_t iv_exc[IV_LEN] = {0xdf, 0x51};
        uint8_t *key, *iv;
        int err = get_encryption_params(path, &key, &iv);
        rv = compare_strings("/sieqaqk", path, "get_encryption_params") ? 1 : rv;
        rv = compare_arrays(key_exc, key, KEY_LEN, "get_encryption_params") ? 1 : rv;
        rv = compare_arrays(iv_exc, iv, IV_LEN, "get_encryption_params") ? 1 : rv;
        assert(err == 0);
    }

    return rv;
}
