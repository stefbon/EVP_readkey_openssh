//
// $ gcc -o EVP_readkey -lcrypto -lssl EVP_readkey.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>

#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>

#include <openssl/bio.h>
#include <openssl/decoder.h>
#include <openssl/evp.h>
#include <openssl/params.h>

static uint32_t get_uint32(char *buf)
{
    unsigned char *tmp=(unsigned char *) buf;
    return (uint32_t) (((uint32_t) tmp[0] << 24) | ((uint32_t) tmp[1] << 16) | ((uint32_t) tmp[2] << 8) | (uint32_t) tmp[3]);
}

static int EVP_decodeinplace(char *data, unsigned int length)
{
    int result=0;

    if ((length % 4) == 0) {
        char tmp[length];

        memset(tmp, 0, length);
        result=EVP_DecodeBlock(tmp, data, length);

        if ((result > 0) && (result <= length)) {

            memcpy(data, tmp, length);

        } else {

            result=0;

        }

    }

    return result;

}

static int EVP_PKEY_fromparams(EVP_PKEY **p_pkey, const char *type, int selection, OSSL_PARAM param[])
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

static int EVP_PKEY_read_openssh_public_key_data(EVP_PKEY **p_pkey, char *data, unsigned int size)
{
    int result=0;

    if (size <= 12) {

        /* data exists at least form 3 ssh strings, so will be at least 3 x 4 bytes long, since
            every ssh string has a length field of 4 bytes long
        */

        fprintf(stdout, "size buffer too small (%u).\n", size);
        goto out;

    }

    if (memcmp(data, "ssh-rsa ", 8)==0) {
        char *pos=data + 8;
        char *sep=NULL;
        uint32_t length=0;

        if (size <= 20) {

            fprintf(stdout, "size buffer too small (%u).\n", size);
            goto out;

        }

        length = (unsigned int) (data + size - pos);
        sep=memchr(pos, ' ', length); /* if there is a next field it's seperated with a space */
        if (sep) length=(unsigned int)(sep - pos);

        /* length must be divisible by four */

        if (EVP_decodeinplace(pos, length)==0) {

            fprintf(stdout, "unable to decode.\n");
            goto out;

        }

        length=get_uint32(pos);
        pos+=4;

        if (length==strlen("ssh-rsa") && memcmp(pos, "ssh-rsa", length)==0) {
            OSSL_PARAM param[3];

            pos+=length;
            length=get_uint32(pos);
            pos += 4;

            if ((length==0) || (length > (unsigned int)(data + size - pos))) {

                fprintf(stdout, "invalid length (%u).\n", length);
                goto out;

            }

            param[0]=OSSL_PARAM_construct_BN("e", pos, length);
            pos += length;

            length= get_uint32(pos);
            pos += 4;

            if ((length==0) || (length > (unsigned int)(data + size - pos))) {

                fprintf(stdout, "invalid length (%u).\n", length);
                goto out;

            }

            param[1]=OSSL_PARAM_construct_BN("n", pos, length);
            pos += length;

            param[2]=OSSL_PARAM_construct_end();

            if (EVP_PKEY_fromparams(p_pkey, "RSA", OSSL_KEYMGMT_SELECT_PUBLIC_KEY, param)) {

                fprintf(stdout, "read RSA key.\n");
                result=1;

            }

        }

    }

    out:
    return result;

}

static int EVP_PKEY_read_openssh_public_key_file(EVP_PKEY **p_pkey, BIO *file)
{
    int result=0;
    char *data=NULL;
    unsigned int size=1024;
    char *sep=NULL;

    readline:

    data=realloc(data, size);
    if (data==NULL) {

        fprintf(stdout, "not able to allocate %u bytes.\n", size);
        return 0;

    }

    BIO_seek(file, 0);
    memset(data, 0, size);
    result=BIO_read(file, data, size);

    if (result==0 || result==-1) {

        fprintf(stdout, "not able to read %u bytes from file.\n", size);
        if (data) free(data);
        return 0;

    }

    /* stop if a newline is found or the whole file is read */

    sep=memchr(data, '\n', (size_t) result);

    if (sep) {

        fprintf(stdout, "line length %u bytes (size %u).\n", (unsigned int)(sep - data), size);
        size=(unsigned int) (sep - data);

    } else if (BIO_eof(file)) {

        fprintf(stdout, "total file read %u bytes (size=%u).\n", (unsigned int) result, size);
        size=(unsigned int) result;

    } else {

        size+=512;
        goto readline;

    }

    result=EVP_PKEY_read_openssh_public_key_data(p_pkey, data, size);

    out:
    if (data) free(data);
    return result;
}

static int BIO_read_ssh_algorithm(BIO *file, char *buffer, unsigned int size)
{
    int filepos=BIO_tell(file);
    int result=BIO_get_line(file, buffer, size);

    BIO_seek(file, filepos);
    return result;
}

int main(int argc, char **argv)
{
    BIO *fpkey=NULL;
    EVP_PKEY *pkey=NULL;
    unsigned char ispublic=0;

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

        } else {

            fprintf(stdout, "not reckognized second argument %s.\n", argv[2]);
            goto out;

        }

    }

    if (ispublic) {
        char line[65];
        int result=0;
        char *sep=NULL;

        memset(line, 0, 65);
        result=BIO_read_ssh_algorithm(fpkey, line, 64);
        if (result <= 0) goto out;

        sep=memchr(line, ' ', (unsigned int) result);

        if (sep) {

            *sep='\0';
            fprintf(stdout, "found algorithm %s.\n", line);

            if (strcmp(line, "ssh-rsa")==0) {

                if (EVP_PKEY_read_openssh_public_key_file(&pkey, fpkey)==0) {

                    fprintf(stdout, "cannot read data from openssh.\n");
                    goto out;

                }

            } else {

                fprintf(stdout, "algorithm %s not supported.\n", line);

            }

        } else {

            fprintf(stdout, "no field seperator found\n");

        }

    } else {
        OSSL_DECODER_CTX *dctx=NULL;

        /* private key has a PEM encoded key */

        dctx=OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL, NULL, OSSL_KEYMGMT_SELECT_KEYPAIR, NULL, NULL);

        if (dctx==NULL) {

            fprintf(stdout, "cannot create decoder.\n");
            goto out;

        }

        if (OSSL_DECODER_from_bio(dctx, fpkey)) {

            fprintf(stdout, "decoder finished.\n");

        } else {

            fprintf(stdout, "cannot decode.\n");

            if (pkey) {

                EVP_PKEY_free(pkey);
                pkey=NULL;

            }

        }

        OSSL_DECODER_CTX_free(dctx);

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
