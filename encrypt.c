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

#define MAX_FILES 32
static char *files_to_delete[32] = { 0 };

static bool called_atexit = false;

static void clean_up_files(void)
{
    for (int i = 0; i < MAX_FILES && files_to_delete[i]; i++) {
        unlink(files_to_delete[i]);
        free(files_to_delete[i]);
    }
}

/*
 * This function takes a FILE pointer, and creates an encrypted file from it.
 * The created file is passed to an atexit function so it can be deleted automatically.
 * Args:
 *   filep: original FILE pointer, will be closed and changed for the new encrypted FILE
 *   keyp: will receive the newly generated random key
 *   ivp: will receive the newly generated random IV (if enabled in purr.h)
 */
int encrypt_FILE(FILE **filep, uint8_t **keyp, uint8_t **ivp)
{
    if (!called_atexit) {
        atexit(clean_up_files);
    }

    FILE *input = *filep;

    if (input == stdin)  {
        fputs("currently can't encrypt stdin!\n", stderr);
        return -1;
    }
    struct stat s;
    int errs = fstat(fileno(input), &s);
    if (errs != 0) {
        perror("couldn't stat output!");
        return -1;
    }
    off_t file_size = s.st_size;
    ssize_t blocks = file_size / br_aes_big_BLOCK_SIZE;
    if (blocks * br_aes_big_BLOCK_SIZE < file_size) blocks++;
    file_size = blocks * br_aes_big_BLOCK_SIZE;

    uint8_t *key = calloc(KEY_LEN, 1);
    uint8_t *iv = calloc(IV_LEN, 1);
    if (key == NULL || iv == NULL) {
        perror("allocation failure");
        return -1;
    }

    ssize_t err = getrandom(key, KEY_LEN, 0);
    if (err != KEY_LEN) {
        fputs("getrandom() error!\n", stderr);
        return -1;
    }

    #ifndef NO_RANDOMIZE_IV
    err = getrandom(iv, IV_LEN, 0);
    if (err != IV_LEN) {
        fputs("getrandom() error!\n", stderr);
        return -1;
    }
    #endif

    char temp[] = "/tmp/purrito.XXXXXX";
    int tfd = mkstemp(temp);
    if (tfd < 0) {
        perror("couldn't create temp file");
        return -1;
    } else {
        // add cleanup for file
        int i = 0;
        for (; i < MAX_FILES && files_to_delete[i]; i++);
        if (i == MAX_FILES) {
            fputs("couldn't add file to files_to_delete\n", stderr);
        } else {
            files_to_delete[i] = strdup(temp);
        }
    }
    int errfa = posix_fallocate(tfd, 0, file_size);
    if (errfa) {
        perror("error while fallocating");
        return -1;
    }
    uint8_t *temp_map =
        mmap(NULL, file_size, PROT_WRITE, MAP_SHARED, tfd, 0);
    if (temp_map == NULL) {
        perror("mmap failure");
        return -1;
    }
    close(tfd);

    for (ssize_t i = 0; i < blocks; i++) {
        // zero padding for the last round
        uint8_t tmp[br_aes_big_BLOCK_SIZE]  = { 0 };
        fread(tmp, 1, br_aes_big_BLOCK_SIZE, input);
        memcpy(temp_map + i * br_aes_big_BLOCK_SIZE, tmp, br_aes_big_BLOCK_SIZE);
    }

    br_aes_big_cbcenc_keys br = { 0 };
    br_aes_big_cbcenc_init(&br, key, KEY_LEN);
    br_aes_big_cbcenc_run(&br, iv, temp_map, file_size);

    fclose(input);
    munmap(temp_map, file_size);

    // pass pointers to caller
    *filep = fopen(temp, "r");
    if (input == NULL) {
        perror("couldn't read temp file");
        return -1;
    }
    *keyp  = key;
    *ivp = iv;

    return 0;
}
