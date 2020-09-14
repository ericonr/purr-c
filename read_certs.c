#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "read_certs.h"
#include "mmap_file.h"

struct append_dn_status {
    uint8_t *dn;
    size_t n, size;
};

struct create_tas {
    br_x509_trust_anchor *ta;
    size_t n, size;
};

static int append_ta(struct create_tas *ct, br_x509_trust_anchor ta)
{
    if (ct->n + 1 > ct->size) {
        if (ct->size) {
            size_t tmp = ct->size * 2;
            ct->ta = realloc(ct->ta, tmp * sizeof(ta));
            if (ct->ta == NULL) {
                perror("realloc()");
                return -1;
            }
            ct->size = tmp;
        } else {
            size_t tmp = 64;
            ct->ta = malloc(tmp * sizeof(ta));
            if (ct->ta == NULL) {
                perror("malloc()");
                return -1;
            }
            ct->size = tmp;
        }
    }

    ct->ta[ct->n++] = ta;

    return 0;
}

static void append_dn(void *ctx, const void *buf, size_t len)
{
    struct append_dn_status *s = ctx;
    if (s->n + len > s->size) {
        if (s->size) {
            size_t tmp = s->size;
            while (s->n + len > tmp) {
                tmp *= 2;
            }
            s->dn = realloc(s->dn, tmp);
            if (s->dn == NULL) {
                perror("realloc()");
                return;
            }
            s->size = tmp;
        } else {
            // no memory had been allocated
            size_t tmp = 256;
            while (len > tmp) {
                tmp *= 2;
            }
            s->dn = malloc(tmp);
            if (s->dn == NULL) {
                perror("malloc()");
                return;
            }
            s->size = tmp;
        }
    }

    memcpy(s->dn + s->n, buf, len);
    s->n += len;
}

static void push_x509(void *dest_ctx, const void *src, size_t len)
{
    br_x509_decoder_context *dest = dest_ctx;
    br_x509_decoder_push(dest, src, len);
}

size_t bearssl_read_certs(br_x509_trust_anchor **final_ta)
{
    char *cert_path = getenv("CA_CERT_SSL_FILE");
    if (cert_path == NULL) {
        cert_path = "/etc/ssl/certs.pem";
    }

    struct mmap_file cert_map = create_mmap_from_file(cert_path, PROT_READ);
    if (ERROR_MMAP(cert_map)) {
        perror("create_mmap_from_file()");
        return 0;
    }

    off_t len = cert_map.size;
    uint8_t *data = cert_map.data;

    br_pem_decoder_context pem;
    br_x509_decoder_context x509;
    br_pem_decoder_init(&pem);
    br_pem_decoder_setdest(&pem, push_x509, &x509);

    struct append_dn_status dn_status;
    struct create_tas new_ta = { 0 };

    while (len > 0) {
        size_t pushed = br_pem_decoder_push(&pem, data, len);
        data += pushed;
        len -= pushed;

        switch(br_pem_decoder_event(&pem)) {
            const char *name;
            int err;

            case 0:
                break;
            case BR_PEM_BEGIN_OBJ:
                name = br_pem_decoder_name(&pem);
                if (strcmp(name, "CERTIFICATE") == 0) {
                    memset(&dn_status, 0, sizeof dn_status);
                    br_x509_decoder_init(&x509, append_dn, &dn_status);
                }
                break;
            case BR_PEM_ERROR:
                fputs("br_pem_error!\n", stderr);
                break;
            case BR_PEM_END_OBJ:
                err = br_x509_decoder_last_error(&x509);
                if (err) {
                    fprintf(stderr, "X509 err code: %d\n", err);
                } else {
                    // decoded succesfully, now to get the data
                    br_x509_trust_anchor ta =
                        {.flags = br_x509_decoder_isCA(&x509) ? BR_X509_TA_CA : 0};

                    // DN
                    uint8_t *old = dn_status.dn;
                    // shorten the DN, if possible
                    dn_status.dn = realloc(dn_status.dn, dn_status.n);
                    if (dn_status.dn == NULL) {
                        perror("realloc()");
                        dn_status.dn = old;
                    }
                    br_x500_name dn = {.data = dn_status.dn, .len = dn_status.n};
                    // copy into final struct
                    ta.dn = dn;


                    br_x509_pkey *pkey = br_x509_decoder_get_pkey(&x509);
                    br_x509_pkey new_key = { 0 };
                    if (pkey->key_type == BR_KEYTYPE_RSA) {
                        br_rsa_public_key k = pkey->key.rsa;
                        br_rsa_public_key rsa =
                            {.n = malloc(k.nlen), .nlen = k.nlen,
                             .e = malloc(k.elen), .elen = k.elen};
                        if (rsa.n == NULL || rsa.e == NULL) {
                            perror("malloc()");
                            return 0;
                        }
                        memcpy(rsa.n, k.n, k.nlen);
                        memcpy(rsa.e, k.e, k.elen);

                        new_key.key_type = BR_KEYTYPE_RSA;
                        new_key.key.rsa = rsa;
                    } else if (pkey->key_type == BR_KEYTYPE_EC) {
                        br_ec_public_key k = pkey->key.ec;
                        br_ec_public_key ec =
                            {.curve = k.curve,
                             .q = malloc(k.qlen), .qlen = k.qlen};
                        if (ec.q == NULL) {
                            perror("malloc()");
                            return 0;
                        }
                        memcpy(ec.q, k.q, k.qlen);

                        new_key.key_type = BR_KEYTYPE_EC;
                        new_key.key.ec = ec;
                    } else {
                        fputs("non supported key\n", stderr);
                    }

                    ta.pkey = new_key;
                    if (append_ta(&new_ta, ta) == -1) {
                        return 0;
                    }
                }
                break;
        }
    }

    *final_ta = new_ta.ta;
    return new_ta.n;
}
