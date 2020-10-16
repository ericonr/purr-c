#ifndef __READ_CERTS_H_
#define __READ_CERTS_H_

#include <stdio.h>

#include <bearssl.h>

struct trust_anchors {
    br_x509_trust_anchor *ta;
    size_t n, size;
};

void bearssl_read_certs_help(FILE *);
void bearssl_free_certs(struct trust_anchors);
size_t bearssl_read_certs(struct trust_anchors *, const char *);

#endif // __READ_CERTS_H_
