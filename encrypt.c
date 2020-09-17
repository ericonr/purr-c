#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <sys/random.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "libbaseencode/baseencode.h"

#include "purr.h"
#include "mmap_file.h"

/*
 * This function takes an mmap_file struct, and creates an encrypted buffer from it.
 * The created file is passed to an atexit function so it can be deleted automatically.
 * Args:
 *   file: mmap_file for the input file
 *   keyp: will receive the newly generated random key
 *   ivp: will receive the newly generated random IV (if enabled in purr.h)
 */
struct mmap_file encrypt_mmap(struct mmap_file file, uint8_t **keyp, uint8_t **ivp)
{
    off_t file_size = file.size;
    ssize_t blocks = file_size / br_aes_big_BLOCK_SIZE;
    if (blocks * br_aes_big_BLOCK_SIZE < file_size) blocks++;
    file_size = blocks * br_aes_big_BLOCK_SIZE;
    ssize_t padding = file_size - file.size;

    struct mmap_file rv = {.size = file_size, .prot = PROT_MEM, .flags = MAP_MEM};

    uint8_t *key = calloc(KEY_LEN, 1);
    uint8_t *iv = calloc(IV_LEN, 1);
    uint8_t *iv_throwaway = calloc(IV_LEN, 1);
    if (key == NULL || iv == NULL || iv_throwaway == NULL) {
        perror("allocation failure");
        return rv;
    }

    ssize_t err = getrandom(key, KEY_LEN, 0);
    if (err != KEY_LEN) {
        fputs("getrandom() error!\n", stderr);
        return rv;
    }
    #ifdef RANDOMIZE_IV
    #ifdef HAVE_GETRANDOM
    err = getrandom(iv, IV_LEN, 0);
    if (err != IV_LEN) {
        fputs("getrandom() error!\n", stderr);
        return rv;
    }
    #elif HAVE_ARC4RANDOM
    arc4random_buf(iv, IV_LEN);
    #else
    #error "no random buf impl"
    #endif /* GETRANDOM & ARC4RANDOM */
    memcpy(iv_throwaway, iv, IV_LEN);
    #endif /* RANDOMIZE_IV */

    if (!allocate_mmap(&rv)) {
        return rv;
    }

    memcpy(rv.data, file.data, file.size);
    // PKCS#5 padding
    memset(rv.data + file.size, padding, padding);

    br_aes_big_cbcenc_keys br = { 0 };
    br_aes_big_cbcenc_init(&br, key, KEY_LEN);
    br_aes_big_cbcenc_run(&br, iv_throwaway, rv.data, file_size);
    free(iv_throwaway);

    #ifdef ENCODE_BASE_64
    baseencode_error_t berr;
    char *data = base64_encode(rv.data, rv.size, &berr);
    struct mmap_file rv_64 = {.prot = PROT_MEM, .flags = MAP_MEM};
    if (data == NULL) {
        fprintf(stderr, "base64_encode(): error code %d\n", berr);
        return rv_64;
    }

    rv_64.size = strlen(data);
    if (!allocate_mmap(&rv_64)) {
        return rv_64;
    }
    memcpy(rv_64.data, data, rv_64.size);

    free(data);
    free_mmap(&rv);
    rv = rv_64;
    #endif /* ENCODE_BASE_64 */

    free_mmap(&file);

    // pass pointers to caller
    *keyp  = key;
    *ivp = iv;

    return rv;
}

struct mmap_file decrypt_mmap(struct mmap_file file, const uint8_t *key, const uint8_t *iv)
{
    struct mmap_file rv = {.size = file.size, .prot = PROT_MEM, .flags = MAP_MEM};

    #ifdef DECODE_BASE_64
    baseencode_error_t berr;
    size_t data_len;
    // TODO: find out why file.size is weird
    uint8_t *data = base64_decode((char *)file.data, strlen((char *)file.data), &berr, &data_len);
    if (data == NULL) {
        fprintf(stderr, "base64_decode(): error code %d\n", berr);
        return rv;
    }
    // big hack to bypass issues
    //assert(data_len % br_aes_big_BLOCK_SIZE == 0);
    data_len -= data_len % br_aes_big_BLOCK_SIZE;

    rv.size = data_len;
    #endif /* DECODE_BASE_64 */

    if (!allocate_mmap(&rv)) {
        return rv;
    }

    #ifdef DECODE_BASE_64
    memcpy(rv.data, data, rv.size);
    free(data);
    #else
    memcpy(rv.data, file.data, file.size);
    #endif /* DECODE_BASE_64 */

    free_mmap(&file);

    uint8_t *iv_throwaway = calloc(IV_LEN, 1);
    if (iv_throwaway == NULL) {
        perror("calloc()");
        // return bad rv so caller knows there was a failure
        free_mmap(&rv);
        return rv;
    }
    memcpy(iv_throwaway, iv, IV_LEN);

    br_aes_big_cbcdec_keys br = { 0 };
    br_aes_big_cbcdec_init(&br, key, KEY_LEN);
    br_aes_big_cbcdec_run(&br, iv_throwaway, rv.data, rv.size);
    free(iv_throwaway);

    // remove padding - only knows PKCS7
    int padding = rv.data[rv.size - 1];
    if (padding < br_aes_big_BLOCK_SIZE) {
        // data might contain padding
        bool found_padding = true;
        for (int i = 0; i < padding; i++) {
            if (rv.data[rv.size - 1 - i] != padding) {
                found_padding = false;
            }
        }
        if (found_padding) {
            rv.size -= padding;
        }
    }

    return rv;
}
