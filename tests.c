#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/random.h>

#include "purr.h"
#include "mmap_file.h"
#include "gemini.h"

int rv = 0;

static void compare_strings(const char *expected, const char *result, const char *function)
{
    printf("%s(): ", function);
    if (result == NULL || strcmp(expected, result)) {
        rv += 1;
        puts("failure");
        printf("  expected: %s\n  got: %s\n", expected, result);
    } else {
        puts("success");
    }
}

static void compare_arrays(const uint8_t *expected, const uint8_t *result, size_t len, const char *function)
{
    printf("%s(): ", function);
    if (memcmp(expected, result, len)) {
        rv += 1;
        puts("failure");
        printf("  expected: %s\n  got: %s\n", print_hex(expected, len, false), print_hex(result, len, false));
    } else {
        puts("success");
    }
}

int main()
{
    {
        /* formats.c */
        uint8_t buf[] = {0x12, 0x02, 0x12, 0x4c, 0xa8};
        const char *expected = "1202124ca8";
        const char *result = print_hex(buf, sizeof buf, false);
        compare_strings(expected, result, "print_hex");
        const char *hex = "0403124574";
        uint8_t buf_expected[] = {0x04, 0x03, 0x12, 0x45, 0x74};
        uint8_t buf_result[sizeof buf_expected];
        int err = decode_hex(hex, buf_result, sizeof buf_result);
        compare_arrays(buf_expected, buf_result, sizeof buf_result, "decode_hex");
        assert(err == 0);
    }

    {
        /* urls.c */
        const char *dirty = "https://hello.com/ash";
        //char scheme[4096], clean[4096], path[4096], port[16];
        char *scheme = NULL, *clean = NULL, *path = NULL, *port = NULL;
        int portn = clean_up_link(dirty, &scheme, &clean, &path, &port);
        compare_strings("https://", scheme, "clean_up_link");
        compare_strings("hello.com", clean, "clean_up_link");
        compare_strings("/ash", path, "clean_up_link");
        compare_strings("443", port, "clean_up_link");
        assert(portn == HTTPS_PORT);

        free(scheme); scheme = NULL;
        free(clean); clean = NULL;
        free(path); path = NULL;
        free(port); port = NULL;

        dirty = "http://hello.com";
        portn = clean_up_link(dirty, &scheme, &clean, &path, &port);
        compare_strings("http://", scheme, "clean_up_link");
        compare_strings("hello.com", clean, "clean_up_link");
        compare_strings("/", path, "clean_up_link");
        compare_strings("80", port, "clean_up_link");
        assert(portn == HTTP_PORT);

        free(scheme); scheme = NULL;
        free(clean); clean = NULL;
        free(path); path = NULL;
        free(port); port = NULL;

        dirty = "hello.com";
        portn = clean_up_link(dirty, &scheme, &clean, &path, &port);
        compare_strings("http://", scheme, "clean_up_link");
        compare_strings("hello.com", clean, "clean_up_link");
        compare_strings("/", path, "clean_up_link");
        compare_strings("80", port, "clean_up_link");
        assert(portn == HTTP_PORT);

        free(scheme); scheme = NULL;
        free(clean); clean = NULL;
        free(path); path = NULL;
        free(port); port = NULL;

        dirty = "https://bsd.ac/paste.html#sieqaqk_73fe_df51";
        portn = clean_up_link(dirty, &scheme, &clean, &path, &port);
        compare_strings("https://", scheme, "clean_up_link");
        compare_strings("bsd.ac", clean, "clean_up_link");
        compare_strings("/paste.html#sieqaqk_73fe_df51", path, "clean_up_link");
        compare_strings("443", port, "clean_up_link");
        assert(portn == HTTPS_PORT);
        uint8_t key_exc[KEY_LEN] = {0x73, 0xfe};
        uint8_t iv_exc[IV_LEN] = {0xdf, 0x51};
        uint8_t *key, *iv;
        int err = get_encryption_params(path, &key, &iv);
        compare_strings("/sieqaqk", path, "get_encryption_params");
        compare_arrays(key_exc, key, KEY_LEN, "get_encryption_params");
        compare_arrays(iv_exc, iv, IV_LEN, "get_encryption_params");
        assert(err == 0);
    }

    {
        /* mmap_file.c */
        int write_size = 1024 * 1024;
        uint8_t *tmp = calloc(write_size, 4);
        struct mmap_file f = {.size = 2 * write_size, .prot = PROT_MEM, .flags = MAP_MEM};
        assert(allocate_mmap(&f));
        uint8_t *data = malloc(write_size);
        getrandom(data, write_size, 0);
        assert(data);
        int written = write_into_mmap(&f, data, write_size);
        assert(f.offset == written);
        RESET_MMAP(f);
        read_from_mmap(&f, tmp, write_size);
        compare_arrays(data, f.data, write_size, "{write_into,read_from}_mmap");
    }

    {
        /* gemini.c */
        const char *gmi_file = "=> aha/ Aha";
        struct gemini_link_node *head = NULL;
        int n = get_links_from_gmi(gmi_file, &head);
        compare_strings("aha/", head->path, "get_links_from_gmi");
        compare_strings("Aha", head->name, "get_links_from_gmi");
        assert(n == 1);

        gmi_file = "=>  two-a  Two spaces\r\n=>   three\tThree";
        head = NULL;
        n = get_links_from_gmi(gmi_file, &head);
        compare_strings("two-a", head->path, "get_links_from_gmi");
        compare_strings("Two spaces", head->name, "get_links_from_gmi");
        compare_strings("three", head->next->path, "get_links_from_gmi");
        compare_strings("Three", head->next->name, "get_links_from_gmi");
        assert(n == 2);

        const char *root = "/hello";
        const char *add = "piper";
        char *path = walk_gemini_path(root, add);
        compare_strings("/hello/piper", path, "walk_gemini_path");
        root = "/hello/";
        add = "/piper/hi/../../a";
        path = walk_gemini_path(root, add);
        compare_strings("/hello/a", path, "walk_gemini_path");
        root = "/hello/";
        add = "/piper/hi/";
        path = walk_gemini_path(root, add);
        compare_strings("/hello/piper/hi/", path, "walk_gemini_path");
        root = "/hello";
        add = "../../../../..";
        path = walk_gemini_path(root, add);
        compare_strings("/", path, "walk_gemini_path");
    }

    printf("Total errors: %d\n", rv);
    return rv;
}
