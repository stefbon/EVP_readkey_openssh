//
// $ gcc -o testrpkey -lcrypto -lssl EVP_readpkey.c EVP_utils.c openssh-utils.c str-utils.c utils.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>

#include <openssl/bio.h>
#include <openssl/decoder.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "str-utils.h"
#include "utils.h"

#include "EVP_readpkey.h"
#include "EVP_utils.h"
#include "openssh-utils.h"

int main(int argc, char **argv)
{
    BIO *fpkey=NULL;
    EVP_PKEY *pkey=NULL;
    signed char ispublic=-1;
    struct ssh_algorithm_s *guessed=NULL;
    unsigned char secret=0;

    if (argc<2) {

        fprintf(stdout, "not enough parameters.\n");
        goto out;

    }

    fpkey=BIO_new_file(argv[1], "r");

    if (fpkey==NULL) {

        fprintf(stdout, "cannot open file %s.\n", argv[1]);
        goto out;

    }

    if (argc>=3) {

        if (strcasecmp(argv[2], "public")==0) {

            ispublic=1;

        } else if (strcasecmp(argv[2], "private")==0) {

            ispublic=0;

        } else {

            fprintf(stdout, "not reckognized second argument %s.\n", argv[2]);
            goto out;

        }

    }

    guessed=get_ssh_algorithm_by_filename(argv[1], &secret);

    if ((ispublic==1) || (ispublic==0)) {

        if (secret == ispublic) {

            /* cannot be both true */

            fprintf(stdout, "warning: argument public/private (%i) conflicts with guessed secret (%u) from filename ... ignoring guessed value\n", ispublic, secret);

        }

    } else {

        ispublic=(secret) ? 0 : 1;

    }

    if (ispublic) {
        char line[65]; /* algo names are max 64, use 65 for terminating zero byte */
        struct ssh_algorithm_s *found=NULL;

        memset(line, 0, 65);
        found=BIO_read_ssh_algorithm(fpkey, line, 64);

        if (found) {

            if (guessed && (guessed != found)) {

                fprintf(stdout, "found algorithm %s differs from guessed %s.\n", line, guessed->name);
                goto out;

            }

            fprintf(stdout, "found algorithm %s.\n", line);

            if (OPENSSH_read_public_key_fileline(&pkey, fpkey, found, 1)==0) {

                fprintf(stdout, "cannot read data from openssh.\n");
                goto out;

            }

        } else {

            fprintf(stdout, "algorithm %s not supported/reckognized.\n", line);

        }

    } else {
        struct utils_buffer_s buffer=UTILS_BUFFER_INIT;
        unsigned int format=OPENSSH_check_format(fpkey, &buffer);

        if (format==PKEY_FILE_HEADER_OPENSSH_PRIVATE) {

            if (OPENSSH_read_openssh_format_data(&pkey, &buffer, format, 1, guessed)) {

                fprintf(stdout, "private key read from OPENSSH format.\n");

            }

            UTILS_free_buffer(&buffer);

        } else {

            UTILS_free_buffer(&buffer);

            if (format==PKEY_FILE_HEADER_RSA_PRIVATE) {

                /* read using the openssl build in decoder */

                if (EVP_PKEY_read_with_decoder(&pkey, fpkey, "PEM", 1)) {

                    fprintf(stdout, "private key read from PEM format.\n");

                }

            }

        }

    }

    if (pkey) {
        BIO *outb=BIO_new_fp(stdout, BIO_NOCLOSE);

        if (ispublic) {

            EVP_PKEY_print_public(outb, pkey, 20, NULL);

        } else {

            EVP_PKEY_print_private(outb, pkey, 20, NULL);

        }

        BIO_free(outb);

    } else {

        fprintf(stdout, "pkey not set.\n");

    }

    out:

    if (pkey) EVP_PKEY_free(pkey);
    if (fpkey) BIO_free(fpkey);
    return 0;
}
