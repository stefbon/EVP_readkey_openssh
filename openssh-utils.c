#define _GNU_SOURCE

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

#define OPENSSH_KEY_V1					"openssh-key-v1"

struct pkey_file_header_s {
    unsigned int                                        code;
    const char                                          *header;
    const char                                          *footer;
};

struct pkey_file_header_s openssh_file_headers[] = {
    {   .code                                           = PKEY_FILE_HEADER_OPENSSH_PRIVATE,
        .header                                         = "-----BEGIN OPENSSH PRIVATE KEY-----",
        .footer                                         = "-----END OPENSSH PRIVATE KEY-----",
    },
    {   .code                                           = PKEY_FILE_HEADER_RSA_PRIVATE,
        .header                                         = "-----BEGIN RSA PRIVATE KEY-----",
        .footer                                         = "-----END RSA PRIVATE KEY-----",
    },
    {   .code                                           = 0,
        .header                                         = NULL,
        .footer                                         = NULL,
    },

};

static int get_index_file_header_by_code(unsigned int code)
{
    unsigned int ctr=0;

    while (openssh_file_headers[ctr].header) {

        if (openssh_file_headers[ctr].code==code) break;
        ctr++;

    }

    return (openssh_file_headers[ctr].header) ? ctr : -1;
}

static int find_header_footer_buffer(struct utils_buffer_s *buffer, const char *header, const char *footer, struct ssh_str_s *data)
{
    unsigned int length=0;
    char *found01=NULL;
    char *found02=NULL;

    if (buffer==NULL || buffer->ptr==NULL || header==NULL || footer==NULL) return -1;

    length=strlen(header);
    if (buffer->length<length) return 0;

    found01=memmem(buffer->ptr, buffer->length, header, length);
    if (found01==NULL) return 0;

    fprintf(stdout, "found header %s.\n", header);

    /* look in the buffer ->after<- the header for the footer */

    found02=memmem((char *)(found01 + length), (unsigned int)(buffer->ptr + buffer->length - header - length), footer, strlen(footer));
    if (found02==NULL) return 0;

    fprintf(stdout, "found footer %s.\n", footer);

    if (data) {

        data->str=(char *)(found01 + length);
        data->length=(unsigned int)(found02 - data->str);

    }

    return 1;
}

static unsigned char OPENSSH_test_encoding_algorithm(struct ssh_algorithm_s *found, struct ssh_str_s *encoding_algo)
{
    unsigned char result=0;

    if (strcmp(found->name, "ssh-rsa")==0) {

        result=cmp_ssh_str(encoding_algo, "ssh-rsa", 7);

    } else if (strcmp(found->name, "ssh-ed25519")==0) {

        result=cmp_ssh_str(encoding_algo, "ssh-ed25519", 11);

    }

    return result;
}

int OPENSSH_read_public_key_data(EVP_PKEY **p_pkey, struct ssh_str_s *data, struct ssh_algorithm_s *found)
{
    int result=0;

    if ((strcmp(found->name, "ssh-rsa")==0) || (strcmp(found->name, "ssh-ed25519")==0)) {
        struct ssh_str_s algo=SSH_STRING_INIT;

        if (data->length <= 4) {

            fprintf(stdout, "size buffer too small (%u).\n", data->length);
            goto out;

        }

        if (str_read_string_hlpr(data, &algo)) {
            struct ssh_key_param_s key;

            memset(&key, 0, sizeof(struct ssh_key_param_s));

            /* does the encoding algo match the key algo? */

            if (OPENSSH_test_encoding_algorithm(found, &algo)==0) {

                fprintf(stdout, "encoding algorithm is %.*s but algorithm is %s : no match.\n", algo.length, algo.str, found->name);
                goto out;

            }

            if (cmp_ssh_str(&algo, "ssh-rsa", 7)) {

                key.algoname="ssh-rsa";
                if (str_read_string_hlpr(data, &key.data.rsa.e)==0) goto out;
                if (str_read_string_hlpr(data, &key.data.rsa.n)==0) goto out;

            } else if (cmp_ssh_str(&algo, "ssh-ed25519", 11)) {

                key.algoname="ssh-ed25519";
                if (str_read_string_hlpr(data, &key.data.ed25519.q)==0) goto out;

            }

            if (EVP_PKEY_read_ssh_key_param(p_pkey, &key, 0)) {

                result=1;

            }

        }

    }

    out:
    return result;
}

static int OPENSSH_read_openssh_key_001(struct ssh_str_s *data, struct ssh_str_s *pk, struct ssh_str_s *sk)
{
    struct ssh_str_s ciphername=SSH_STRING_INIT;
    struct ssh_str_s kdfname=SSH_STRING_INIT;
    struct ssh_str_s kdfoptions=SSH_STRING_INIT;
    struct ssh_str_s tmp=SSH_STRING_INIT;
    uint32_t count=0;

    fprintf(stdout, "%s\n", __FUNCTION__);

    /* ssh string ciphername
        20230910: this should be the "none" string */

    if ((str_read_string_hlpr(data, &ciphername)==0) || (cmp_ssh_str(&ciphername, "none", 4)==0)) {

        fprintf(stdout, "ciphername not supported and/or invalid format\n");
        goto errorout;

    }

    /* ssh string kdfname
        20230910: this should be the "none" string*/

    if ((str_read_string_hlpr(data, &kdfname)==0) || (cmp_ssh_str(&kdfname, "none", 4)==0)) {

        fprintf(stdout, "kdf not supported and/or invalid format\n");
        goto errorout;

    }

    /* ssh string kdfoptions
        20230910: this should be an empty string */

    if ((str_read_string_hlpr(data, &kdfoptions)==0) || (cmp_ssh_str(&kdfoptions, NULL, 0)==0)) {

        fprintf(stdout, "kdf options not supported and/or invalid format\n");
        goto errorout;

    }

    /* number of keys */

    if (str_read_uint32_hlpr(data, &count)==0) {

        fprintf(stdout, "error reading count nr keys: invalid format\n");
        goto errorout;

    }

    if ((count==0) || (count>1)) {

        fprintf(stdout, "count %u number of keys not supported\n", count);
        goto errorout;

    }

    /* public key section  */

    init_ssh_string(&tmp);

    if (str_read_string_hlpr(data, &tmp)==0) {

        fprintf(stdout, "public key section invalid format\n");
        goto errorout;

    }

    if (pk) {

        pk->length=tmp.length;
        pk->str=(tmp.length>0) ? tmp.str : NULL;
        pk->flags=tmp.flags;

    }

    /* private key section */

    init_ssh_string(&tmp);

    if (str_read_string_hlpr(data, &tmp)==0) {

        fprintf(stdout, "private key section invalid format\n");
        goto errorout;

    }

    if (tmp.length>12) {
        unsigned int checkint1=0;
        unsigned int checkint2=0;

        if ((str_read_uint32_hlpr(&tmp, &checkint1)==0) || (str_read_uint32_hlpr(&tmp, &checkint2)==0)) {

            fprintf(stdout, "error reading check integers: invalid format\n");
            goto errorout;

        }

        if (checkint1 != checkint2) {

            fprintf(stdout, "both check integers are not the same (%u != %u)\n", checkint1, checkint2);
            goto errorout;

        }

        if (sk) {

            sk->length=tmp.length;
            sk->str=tmp.str;
            sk->flags=tmp.flags;

        }

    }

    /* when here successfull */
    return 1;

    errorout:
    return 0;

}

static int OPENSSH_read_openssh_key_section(struct ssh_str_s *data, struct ssh_key_param_s *key, const char *algorithm, unsigned char secret)
{
    struct ssh_str_s algoname=SSH_STRING_INIT;
    int result=0;

    /* ssh string algoname */

    if (str_read_string_hlpr(data, &algoname)==0) {

        fprintf(stdout, "private key invalid format\n");
        goto out;

    }

    if (algorithm) {

        /* it needs to the same as the algorithm
            (or at least the encoding algorithm should belong to the key algorithm */

        if (cmp_ssh_str(&algoname, algorithm, strlen(algorithm))==0) {

            fprintf(stdout, "expected %s, found algo format %.*s\n", algorithm, algoname.length, algoname.str);
            goto out;

        }

    }

    if (cmp_ssh_str(&algoname, "ssh-rsa", 7)) {

        key->algoname="ssh-rsa";
        if (str_read_string_hlpr(data, &key->data.rsa.e)==0) goto out;
        if (str_read_string_hlpr(data, &key->data.rsa.n)==0) goto out;

        if (secret) {

            if (str_read_string_hlpr(data, &key->data.rsa.d)==0) goto out;
            if (str_read_string_hlpr(data, &key->data.rsa.iqmp)==0) goto out;
            if (str_read_string_hlpr(data, &key->data.rsa.p)==0) goto out;
            if (str_read_string_hlpr(data, &key->data.rsa.q)==0) goto out;
            if (str_read_string_hlpr(data, &key->data.rsa.comment)==0) goto out;

        }

        result=1;

    } else if (cmp_ssh_str(&algoname, "ssh-ed25519", 11)) {

        key->algoname="ssh-ed25519";
        if (str_read_string_hlpr(data, &key->data.ed25519.q)==0) goto out;

        if (secret) {

            if (str_read_string_hlpr(data, &key->data.ed25519.d)==0) goto out;
            if (key->data.ed25519.d.length==64) key->data.ed25519.d.length=32; /* take only the first 32 */
            if (str_read_string_hlpr(data, &key->data.rsa.comment)==0) goto out;

        }

        result=1;

    }

    out:
    return result;

}

int OPENSSH_read_openssh_key(struct ssh_str_s *data, struct ssh_key_param_s *key, const char *algorithm)
{
    unsigned int len=strlen(OPENSSH_KEY_V1);
    int result=0;
    struct ssh_str_s pk=SSH_STRING_INIT;
    struct ssh_str_s sk=SSH_STRING_INIT;

    fprintf(stdout, "%s\n", __FUNCTION__);

    /* version openssh key v1 starts with a zero terminated AUTH_MAGIC */

    if ((data->length > len+1) && memcmp(data->str, OPENSSH_KEY_V1, len)==0 && (data->str[len]==0)) {

        data->str += (len + 1);
        data->length -= (len + 1);

	if (OPENSSH_read_openssh_key_001(data, &pk, &sk)) {

            if (sk.length > 0) {

                result=OPENSSH_read_openssh_key_section(&sk, key, algorithm, 1);
                if (result==0) goto out;

            }

            if ((pk.length>0) && (result==0)) {

                result=OPENSSH_read_openssh_key_section(&pk, key, algorithm, 0);

            }

        }

    }

    out:
    return result;

}

int OPENSSH_read_openssh_format_data(EVP_PKEY **p_pkey, struct utils_buffer_s *buffer, unsigned int formatcode, unsigned char secret, struct ssh_algorithm_s *guessed)
{
    int index = get_index_file_header_by_code(formatcode);
    int result=0;
    struct ssh_str_s data=SSH_STRING_INIT;
    struct ssh_key_param_s key;

    memset(&key, 0, sizeof(struct ssh_key_param_s));

    if (index==-1) {

        fprintf(stdout, "format code %u not reckognized.\n", formatcode);
        return 0;

    }

    if (find_header_footer_buffer(buffer, openssh_file_headers[index].header, openssh_file_headers[index].footer, &data)<=0) {

        fprintf(stdout, "error: header %u not found.\n", formatcode);
        return 0;

    }

    if ((data.str==NULL) || (data.length==0)) {

        fprintf(stdout, "error: no data found.\n");
        return 0;

    }

    /* KEYMATERIAL is encoded base64 */

    if (EVP_decodeinplace(&data, 1)==0) {

        fprintf(stdout, "unable to decode.\n");
        goto out;

    }

    if (formatcode==PKEY_FILE_HEADER_OPENSSH_PRIVATE) {

        result=OPENSSH_read_openssh_key(&data, &key, guessed->name);

        if (result==1) {

            result=EVP_PKEY_read_ssh_key_param(p_pkey, &key, secret);

        }

    } else {

        fprintf(stdout, "formatcode %u not supported.\n", formatcode);

    }


    out:
    return result;

}

static int cb_read_fileline(struct utils_buffer_s *buffer, void *ptr)
{
    int result=0;

    if (buffer->size >= 20480) {

        result = -1;

    } else {
        char *sep=memchr(buffer->ptr, '\n', (size_t) buffer->length);

        if (sep) {
            unsigned int tmp=(unsigned int) (sep - buffer->ptr);

            if (tmp < buffer->length) {
                char *data=buffer->ptr;

                memset(&data[tmp], 0, (buffer->length - tmp));

            }

            *sep='\0';
            buffer->length=tmp;
            result = 1;

        } else if ((buffer->flags & UTILS_READ_FILE_FLAG_EOF)==0) {

            result = 1;

        }

    }

    return result;

}

/* line looks like

        ALGORITHM KEYMATERIAL COMMENT

        (like for rsa keys):

        ssh-rsa ssh-rsa AAAAB3NzaC1......YN user@host

*/

int OPENSSH_read_public_key_fileline(EVP_PKEY **p_pkey, BIO *file, struct ssh_algorithm_s *guessed, unsigned char algoread)
{
    int result=0;
    struct utils_buffer_s buffer=UTILS_BUFFER_INIT;

    if (UTILS_read_file(file, &buffer, 0, cb_read_fileline, NULL, 0)==1) {
        char *sep=NULL;
        struct ssh_str_s data=SSH_STRING_INIT;

        if (algoread==0) {

            sep=memchr(buffer.ptr, ' ', buffer.length);

            if (sep) {
                unsigned int length=(unsigned int)(sep - buffer.ptr);
                char tmpname[length + 1];
                struct ssh_algorithm_s *found=NULL;

                memcpy(tmpname, buffer.ptr, length);
                tmpname[length]='\0';

                found=get_ssh_algorithm_by_name(tmpname);

                if (found) {

                    if (guessed && (guessed != found)) {

                        fprintf(stdout, "found algorithm %s differs from guessed %s.\n", tmpname, guessed->name);
                        goto out;

                    }

                } else {

                    fprintf(stdout, "found algorithm %s not supported.\n", tmpname);
                    goto out;

                }

                /* isolate the second field == KEYMATERIAL */

                data.str=(char *)(buffer.ptr + length + 1);
                data.length=buffer.length - length - 1;

            } else {

                fprintf(stdout, "no seperator found.\n");
                goto out;

            }

        } else {

            data.str=buffer.ptr;
            data.length=buffer.length;

        }

        sep=memchr(data.str, ' ', data.length);
        if (sep) data.length=(unsigned int)(sep - data.str);

        /* KEYMATERIAL is encoded base64 */

        if (EVP_decodeinplace(&data, 0)==0) {

            fprintf(stdout, "unable to decode.\n");
            goto out;

        }

        result=OPENSSH_read_public_key_data(p_pkey, &data, guessed);

    }

    out:
    UTILS_free_buffer(&buffer);
    return result;
}

/* callback to check a specific header is present in a file */

static int cb_read_header(struct utils_buffer_s *buffer, void *ptr)
{
    int result=0;

    if (buffer->size >= 20480) {

        result = -1;

    } else if ((buffer->flags & UTILS_READ_FILE_FLAG_EOF)==0) {

        result = 0;

    } else {
        unsigned int ctr=0;

        while (openssh_file_headers[ctr].header) {

            if (find_header_footer_buffer(buffer, openssh_file_headers[ctr].header, openssh_file_headers[ctr].footer, NULL)==1) {

                result=openssh_file_headers[ctr].code;
                fprintf(stdout, "found format code %u.\n", openssh_file_headers[ctr].code);
                break;

            }

            ctr++;

        }

        /* check not found */
        if (openssh_file_headers[ctr].header==NULL) result=-1;

    }

    return result;

}

unsigned int OPENSSH_check_format(BIO *file, struct utils_buffer_s *buffer)
{
    return UTILS_read_file(file, buffer, 0, cb_read_header, NULL, (UTILS_READ_FILE_FLAG_RESET_FILEPOS));
}
