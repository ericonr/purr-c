#ifndef __MMAP_FILE_H_
#define __MMAP_FILE_H_

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/mman.h>

#define RESET_MMAP(file) do{(file).offset = 0;}while(0);
#define ERROR_MMAP(file) ((file).data == MAP_FAILED || (file).data == NULL)

// definitions for memory backed mappings
#define PROT_MEM (PROT_WRITE | PROT_READ)
#define MAP_MEM (MAP_ANONYMOUS | MAP_PRIVATE)

// 128KiB
#define OUTPUT_FILE_SIZE (128 * 1024)

struct mmap_file {
    uint8_t *data;
    off_t size, offset;
    int prot, flags;
    FILE *stream;
    bool use_stream;
};

/* mmap_file.c */
bool allocate_mmap(struct mmap_file *);
void free_mmap(struct mmap_file *);
struct mmap_file create_mmap_from_FILE(FILE *, const char *);
struct mmap_file create_mmap_from_file(const char *, int);
int read_from_mmap(struct mmap_file *, int);
int write_into_mmap(struct mmap_file *, const uint8_t *, int);

/* encrypt.c */
struct mmap_file encrypt_mmap(struct mmap_file, uint8_t **, uint8_t **);
struct mmap_file decrypt_mmap(struct mmap_file, const uint8_t *, const uint8_t *);

#endif // __MMAP_FILE_H_
