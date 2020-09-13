#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/random.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "libbaseencode/baseencode.h"

#include "purr.h"

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

    struct mmap_file rv =
        {.size = file_size, .prot = PROT_WRITE | PROT_READ, .flags = MAP_ANONYMOUS | MAP_PRIVATE};

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
    #ifndef NO_RANDOMIZE_IV
    err = getrandom(iv, IV_LEN, 0);
    memcpy(iv_throwaway, iv, IV_LEN);
    if (err != IV_LEN) {
        fputs("getrandom() error!\n", stderr);
        return rv;
    }
    #endif /* NO_RANDOMIZE_IV */

    rv.data = mmap(NULL, rv.size, rv.prot, rv.flags, -1, 0);
    if (ERROR_MMAP(rv)) {
        perror("mmap()");
        return rv;
    }

    memcpy(rv.data, file.data, file.size);
    ssize_t i = 0;
    for (; i < (file_size - file.size); i++) {
        rv.data[file.size + i] = file.data[file.size + i];
    }
    memset(rv.data, 0, (file_size - file.size - i));

    br_aes_big_cbcenc_keys br = { 0 };
    br_aes_big_cbcenc_init(&br, key, KEY_LEN);
    br_aes_big_cbcenc_run(&br, iv_throwaway, rv.data, file_size);

    #ifdef ENCODE_BASE_64
    baseencode_error_t berr;
    const char *data = base64_encode(rv.data, rv.size, &berr);
    if (data == NULL || berr != SUCCESS) {
        fprintf(stderr, "base64_encode(): error code %d\n", berr);
        // TODO: returns good rv
        return rv;
    }
    size_t len = strlen(data);
    struct mmap_file rv_64 =
        {.size = len, .prot = PROT_WRITE | PROT_READ, .flags = MAP_ANONYMOUS | MAP_PRIVATE};
    rv_64.data = mmap(NULL, rv_64.size, rv_64.prot, rv_64.flags, -1, 0);
    if (ERROR_MMAP(rv_64)) {
        perror("mmap()");
        // TODO: returns good rv
        return rv;
    }
    memcpy(rv_64.data, data, len);
    munmap(rv.data, rv.size);
    rv = rv_64;
    #endif /* ENCODE_BASE_64 */

    munmap(file.data, file.size);

    // pass pointers to caller
    *keyp  = key;
    *ivp = iv;

    return rv;
}
