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
#include "openssh-utils.h"

static struct ssh_algorithm_s algorithms[] = {
    {   .name           = "ssh-rsa",
        .filename       = "id_rsa",
        .minlength      = 8,
    },
    {   .name           = "ssh-ed25519",
        .filename       = "id_ed25519",
        .minlength      = 4,
    },
    {   .name           = NULL,
        .filename       = NULL,
        .minlength      = 0,
    },

};

struct ssh_algorithm_s *get_ssh_algorithm_by_name(char *name)
{
    unsigned int ctr=0;
    struct ssh_algorithm_s *found=NULL;

    while (algorithms[ctr].name) {

        if (strcmp(algorithms[ctr].name, name)==0) {

            found=&algorithms[ctr];
            break;

        }

        ctr++;

    }

    return found;
}

struct ssh_algorithm_s *get_ssh_algorithm_by_filename(char *filepath, unsigned char *p_secret)
{
    unsigned int ctr=0;
    struct ssh_algorithm_s *found=NULL;
    char *sep=NULL;
    unsigned int len=0;
    char *filename=NULL;

    if (filepath==NULL || strlen(filepath)==0) return NULL;
    sep=strrchr(filepath, '/');
    filename=(sep) ? (char *)(sep + 1) : filepath;

    /* if the file ends with ".pub" this part should be ignored */

    sep=strrchr(filename, '.');
    len = (sep && (strcmp(sep, ".pub")==0)) ? (unsigned int) (sep - filename) : strlen(filename);
    if (p_secret) *p_secret=(len == strlen(filename)) ? 1 : 0;

    while (algorithms[ctr].name) {

        if (memcmp(algorithms[ctr].filename, filename, len)==0) {

            found=&algorithms[ctr];
            break;

        }

        ctr++;

    }

    return found;
}

struct ssh_algorithm_s *BIO_read_ssh_algorithm(BIO *file, char *buffer, unsigned int size)
{
    struct ssh_algorithm_s *found=NULL;
    int filepos=BIO_tell(file);
    int result=BIO_get_line(file, buffer, size);

    if (result>0) {
        unsigned int length=0;
        unsigned int ctr=0;

        while (algorithms[ctr].name) {

            length=strlen(algorithms[ctr].name);

            if ((result > length) && (memcmp(buffer, algorithms[ctr].name, length)==0) && (buffer[length]==' ')) {

                found=&algorithms[ctr];
                filepos += length + 1; /* set filepos after the algorithm: start reading here for the rest of the line/file */
                buffer[length]='\0';
                break;

            }

            ctr++;

        }

    }

    BIO_seek(file, filepos);
    return found;
}


int EVP_decodeinplace(struct ssh_str_s *data, unsigned char removenl)
{
    int result=0;

    if (removenl) {
        char *sep=data->str;

        searchnl:

        sep=memchr(sep, '\n', (data->str + data->length - sep));

        if (sep) {

            memmove(sep, sep+1, (unsigned int)(data->str + data->length - (sep + 1)));
            data->length--;
            goto searchnl;

        }

    }

    /* length must be divisible by four */

    if ((data->length % 4) == 0) {
        char tmp[data->length];

        memset(tmp, 0, data->length);
        result=EVP_DecodeBlock(tmp, data->str, data->length);

        if ((result > 0) && (result <= data->length)) {

            memcpy(data->str, tmp, data->length);

        } else {

            result=0;

        }

    }

    return result;

}

int EVP_PKEY_fromparams(EVP_PKEY **p_pkey, const char *type, int selection, OSSL_PARAM param[])
{
    EVP_PKEY_CTX *ctx=NULL;
    int result=0;

    ctx=EVP_PKEY_CTX_new_from_name(NULL, type, NULL);

    if (ctx==NULL) {

        fprintf(stdout, "unable to create pkey ctx.\n");
        goto out;

    }

    if (EVP_PKEY_fromdata_init(ctx) <= 0) {

        fprintf(stdout, "unable to create pkey ctx.\n");
        goto out;

    }

    if (EVP_PKEY_fromdata(ctx, p_pkey, selection, param) <= 0) {

        fprintf(stdout, "unable to create pkey from data.\n");
        goto out;

    }

    result=1;

    out:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return result;

}

/* convert key param from ssh key struct to OSSL PARAM */

int EVP_PKEY_read_ssh_key_param(EVP_PKEY **p_pkey, struct ssh_key_param_s *key, unsigned char secret)
{
    int result=0;
    unsigned int selection=(secret) ? OSSL_KEYMGMT_SELECT_KEYPAIR : OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

    if (strcmp(key->algoname, "ssh-rsa")==0) {
        unsigned int count=(secret) ? 4 : 3;
        OSSL_PARAM param[count];
        unsigned int ctr=0;

        param[ctr++]=OSSL_PARAM_construct_BN("e", key->data.rsa.e.str, key->data.rsa.e.length);
        param[ctr++]=OSSL_PARAM_construct_BN("n", key->data.rsa.n.str, key->data.rsa.n.length);
        if (secret) param[ctr++]=OSSL_PARAM_construct_BN("d", key->data.rsa.d.str, key->data.rsa.d.length);
        param[ctr++]=OSSL_PARAM_construct_end();

        if (EVP_PKEY_fromparams(p_pkey, "RSA", selection, param)) {

            fprintf(stdout, "created RSA key.\n");
            result=1;

        }

    } else if (strcmp(key->algoname, "ssh-ed25519")==0) {
        unsigned int count=(secret) ? 3 : 2;
        OSSL_PARAM param[count];
        unsigned int ctr=0;

        param[ctr++]=OSSL_PARAM_construct_octet_string("pub", key->data.ed25519.q.str, key->data.ed25519.q.length);
        if (secret) param[ctr++]=OSSL_PARAM_construct_octet_string("priv", key->data.ed25519.d.str, key->data.ed25519.d.length);
        param[ctr++]=OSSL_PARAM_construct_end();

        if (EVP_PKEY_fromparams(p_pkey, "ED25519", selection, param)) {

            fprintf(stdout, "created ED25519 key.\n");
            result=1;

        }

    }

    out:
    return result;

}

/* read a file using an openssl build in decoder (like "PEM") */

int EVP_PKEY_read_with_decoder(EVP_PKEY **p_pkey, BIO *fpkey, char *name, unsigned char secret)
{
    unsigned int selection=(secret) ? OSSL_KEYMGMT_SELECT_KEYPAIR : OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    OSSL_DECODER_CTX *dctx=NULL;
    int result=0;

    dctx=OSSL_DECODER_CTX_new_for_pkey(p_pkey, name, NULL, NULL, selection, NULL, NULL);

    if (dctx==NULL) {

        fprintf(stdout, "cannot create decoder.\n");
        goto out;

    }

    if (OSSL_DECODER_from_bio(dctx, fpkey)) {

        fprintf(stdout, "decoder finished.\n");
        result=1;

    } else {

        fprintf(stdout, "cannot decode.\n");

    }

    out:

    OSSL_DECODER_CTX_free(dctx);
    return result;
}
