#ifndef __READ_CERTS_H_
#define __READ_CERTS_H_

#include <bearssl.h>

void bearssl_free_certs(br_x509_trust_anchor **, size_t);
size_t bearssl_read_certs(br_x509_trust_anchor **);

#endif // __READ_CERTS_H_
