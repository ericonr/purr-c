#ifndef __MMAP_FILE_H_
#define __MMAP_FILE_H_

#include <stdint.h>
#include <sys/mman.h>

#define RESET_MMAP(file) do{(file).offset = 0; (file).cursor = 0}while(0);
#define ERROR_MMAP(file) ((file).data == MAP_FAILED || (file).data == NULL)
#define CLOSE_MMAP(file) do{if((file).data != MAP_FAILED && (file).data != NULL) munmap((file).data, (file).size);}while(0);

// definitions for memory backed mappings
#define PROT_MEM (PROT_WRITE | PROT_READ)
#define MAP_MEM (MAP_ANONYMOUS | MAP_PRIVATE)

// 128KiB
#define OUTPUT_FILE_SIZE (128 * 1024)

struct mmap_file {
    uint8_t *data, *cursor;
    off_t size, offset;
    int prot, flags;
};

/* mmap_file.c */
struct mmap_file create_mmap_from_file(const char *, int);
int read_from_mmap(struct mmap_file *, int);
int write_into_mmap(struct mmap_file *, const uint8_t *, int);

/* encrypt.c */
struct mmap_file encrypt_mmap(struct mmap_file, uint8_t **, uint8_t **);
struct mmap_file decrypt_mmap(struct mmap_file, const uint8_t *, const uint8_t *);

#endif // __MMAP_FILE_H_
