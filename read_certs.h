#ifndef __READ_CERTS_H_
#define __READ_CERTS_H_

#include <stdio.h>

#include <bearssl.h>

void bearssl_read_certs_help(FILE *);
void bearssl_free_certs(br_x509_trust_anchor **, size_t);
size_t bearssl_read_certs(br_x509_trust_anchor **, const char *);

#endif // __READ_CERTS_H_
