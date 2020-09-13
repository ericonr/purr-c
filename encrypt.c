#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/random.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "purr.h"

int encrypt_FILE(FILE **filep, uint8_t **keyp, uint8_t **ivp, char **tempp)
{
    FILE *input = *filep;
    uint8_t *key  = *keyp;
    uint8_t *iv = *ivp;
    char *temp = *tempp;

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

    key = calloc(KEY_LEN, 1);
    iv = calloc(IV_LEN, 1);
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

    temp = strdup("/tmp/purrito.XXXXXX");
    int tfd = mkstemp(temp);
    if (tfd < 0) {
        perror("couldn't create temp file");
        return -1;
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

    input = fopen(temp, "r");
    if (input == NULL) {
        perror("couldn't read temp file");
        return -1;
    }
    fstat(fileno(input), &s);
    fprintf(stderr, "output file size: %lu\n", s.st_size);

    return 0;
}
