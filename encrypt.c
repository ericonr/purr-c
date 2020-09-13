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

    struct mmap_file rv = {.size = file_size, .prot = PROT_WRITE | PROT_READ, .flags = MAP_ANONYMOUS | MAP_PRIVATE};

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
    #endif

    rv.data =
        mmap(NULL, rv.size, rv.prot, rv.flags, -1, 0);
    if (rv.data == MAP_FAILED) {
        perror("mmap failure");
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

    munmap(file.data, file.size);

    // pass pointers to caller
    *keyp  = key;
    *ivp = iv;

    return rv;
}
