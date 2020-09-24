#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/random.h>

#include "purr.h"
#include "mmap_file.h"
#include "gemini.h"

static int compare_strings(const char *expected, const char *result, const char *function)
{
    int rv = 0;

    printf("%s(): ", function);
    if (result == NULL || strcmp(expected, result)) {
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
        //char scheme[4096], clean[4096], path[4096], port[16];
        char *scheme = NULL, *clean = NULL, *path = NULL, *port = NULL;
        int portn = clean_up_link(dirty, &scheme, &clean, &path, &port);
        rv = compare_strings("https://", scheme, "clean_up_link") ? 1 : rv;
        rv = compare_strings("hello.com", clean, "clean_up_link") ? 1 : rv;
        rv = compare_strings("/ash", path, "clean_up_link") ? 1 : rv;
        rv = compare_strings("443", port, "clean_up_link") ? 1 : rv;
        assert(portn == HTTPS_PORT);

        free(scheme); scheme = NULL;
        free(clean); clean = NULL;
        free(path); path = NULL;
        free(port); port = NULL;

        dirty = "http://hello.com";
        portn = clean_up_link(dirty, &scheme, &clean, &path, &port);
        rv = compare_strings("http://", scheme, "clean_up_link") ? 1 : rv;
        rv = compare_strings("hello.com", clean, "clean_up_link") ? 1 : rv;
        rv = compare_strings("/", path, "clean_up_link") ? 1 : rv;
        rv = compare_strings("80", port, "clean_up_link") ? 1 : rv;
        assert(portn == HTTP_PORT);

        free(scheme); scheme = NULL;
        free(clean); clean = NULL;
        free(path); path = NULL;
        free(port); port = NULL;

        dirty = "https://bsd.ac/paste.html#sieqaqk_73fe_df51";
        portn = clean_up_link(dirty, &scheme, &clean, &path, &port);
        rv = compare_strings("https://", scheme, "clean_up_link") ? 1 : rv;
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

    {
        /* mmap_file.c */
        int write_size = 1024 * 1024;
        struct mmap_file f = {.size = 2 * write_size, .prot = PROT_MEM, .flags = MAP_MEM};
        assert(allocate_mmap(&f));
        uint8_t *data = malloc(write_size);
        getrandom(data, write_size, 0);
        assert(data);
        int written = write_into_mmap(&f, data, write_size);
        assert(f.offset == written);
        RESET_MMAP(f);
        read_from_mmap(&f, write_size);
        rv = compare_arrays(data, f.data, write_size, "{write_into,read_from}_mmap") ? 1 : rv;
    }

    {
        /* gemini.c */
        const char *gmi_file = "=> aha/ Aha";
        struct gemini_link_node *head = NULL;
        int n = get_links_from_gmi(gmi_file, &head);
        rv = compare_strings("aha/", head->path, "get_links_from_gmi") ? 1 : rv;
        rv = compare_strings("Aha", head->name, "get_links_from_gmi") ? 1 : rv;
        assert(n == 1);

        gmi_file = "=>  two-a  Two spaces\r\n=>   three\tThree";
        head = NULL;
        n = get_links_from_gmi(gmi_file, &head);
        rv = compare_strings("two-a", head->path, "get_links_from_gmi") ? 1 : rv;
        rv = compare_strings("Two spaces", head->name, "get_links_from_gmi") ? 1 : rv;
        rv = compare_strings("three", head->next->path, "get_links_from_gmi") ? 1 : rv;
        rv = compare_strings("Three", head->next->name, "get_links_from_gmi") ? 1 : rv;
        assert(n == 2);
    }

    return rv;
}
