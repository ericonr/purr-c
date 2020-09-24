#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "mmap_file.h"

bool allocate_mmap(struct mmap_file *f)
{
    f->data = mmap(NULL, f->size, f->prot, f->flags, -1, 0);
    if (ERROR_MMAP(*f)) {
        perror("mmap()");
        return false;
    }
    return true;
}

void free_mmap(struct mmap_file *f)
{
    if (f->data == MAP_FAILED || f->data == NULL) {
        return;
    }

    if (f->use_stream) {
        fclose(f->stream);
    } else {
        munmap(f->data, f->size);
    }

    f->data = NULL;
    f->size = 0;
}

struct mmap_file create_mmap_from_FILE(FILE *stream, const char *mode)
{
    struct mmap_file rv = { 0 };
    if (*mode == 'w') {
        rv.prot = PROT_WRITE;
    } else if (*mode == 'r') {
        rv.prot = PROT_READ;
    } else {
        // show caller that they used the wrong values
        errno = EINVAL;
        return rv;
    }

    rv.stream = stream;
    rv.use_stream = true;
    // make data pointer valid, for error checking
    rv.data = (void *)0x01;

    return rv;
}

struct mmap_file create_mmap_from_file(const char *name, int prot)
{
    struct mmap_file rv = {.prot = prot};
    int fd;
    if (prot == PROT_READ) {
        fd = open(name, O_RDONLY | O_CLOEXEC);
        rv.flags = MAP_PRIVATE;

        if (fd == -1) {
            return rv;
        }

        struct stat st;
        if (fstat(fd, &st) == -1) {
            perror("fstat()");
            return rv;
        }
        rv.size = st.st_size;
    } else if (prot == PROT_WRITE) {
        fd = open(name, O_WRONLY | O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR);
        rv.flags = MAP_PRIVATE;

        if (fd == -1) {
            return rv;
        }

        // ftruncate is good enough for now
        // TODO: we can truncate again once we know the content-size,
        // otherwise this will leave the file with the wrong size
        if (0 && ftruncate(fd, OUTPUT_FILE_SIZE) == -1) {
            return rv;
        }
        rv.size = OUTPUT_FILE_SIZE;
    } else if (name == NULL && prot == PROT_MEM) {
        fd = -1;
        rv.flags = MAP_ANONYMOUS | MAP_PRIVATE;
        rv.size = OUTPUT_FILE_SIZE;
    } else {
        fputs("unsupported prot flags\n", stderr);
        errno = 0;
        return rv;
    }

    rv.data = mmap(NULL, rv.size, rv.prot, rv.flags, fd, 0);
    if (fd > 0) close(fd);

    return rv;
}

int read_from_mmap(struct mmap_file *file, uint8_t *buffer, int n)
{
    assert(file->prot & PROT_READ);

    if (file->use_stream) {
        // TODO: returns bogus values, transmissions end up empty
        return fread(buffer, 1, n, file->stream);
    }

    if (file->size == file->offset) {
        // can't read any more
        return 0;
    }

    ssize_t max = file->size - file->offset;
    const uint8_t *cursor = file->data + file->offset;
    if (n < max) {
        // can fit the read
        file->offset += n;
    } else {
        // can read less than n
        file->offset = file->size;
        n = max;
    }

    memcpy(buffer, cursor, n);
    return n;
}

int write_into_mmap(struct mmap_file *file, const uint8_t *buffer, int n)
{
    assert(file->prot & PROT_WRITE);

    // short circuiting logic for writing into a file directly
    if (file->use_stream) {
        n = fwrite(buffer, 1, n, file->stream);
        file->size += n;
        return n;
    }

    if (file->size == file->offset) {
        return -1;
    }

    ssize_t max = file->size - file->offset;
    uint8_t *cursor = file->data + file->offset;
    if (n < max) {
        file->offset += n;
    } else {
        file->offset = file->size;
        n = max;
    }

    memcpy(cursor, buffer, n);
    return n;
}
