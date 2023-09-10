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

void init_ssh_string(struct ssh_str_s *str)
{
    str->length=0;
    str->str=NULL;
    str->flags=0;
}

uint32_t get_uint32(char *buf)
{
    unsigned char *tmp=(unsigned char *) buf;
    return (uint32_t) (((uint32_t) tmp[0] << 24) | ((uint32_t) tmp[1] << 16) | ((uint32_t) tmp[2] << 8) | (uint32_t) tmp[3]);
}

unsigned int read_ssh_str(char *buffer, unsigned int size, struct ssh_str_s *str)
{
    char *pos=buffer;

    str->flags |= SSH_STRING_FLAG_INVALID;

    if (size >= 4) {

        str->length=get_uint32(pos);
        pos += 4;

        if ((4 + str->length) <= size) {

            str->str=pos;
            pos += str->length;
            str->flags &= ~SSH_STRING_FLAG_INVALID;

        }

    }

    return (unsigned int)(pos - buffer);
}

int cmp_ssh_str(struct ssh_str_s *stra, char *data, unsigned int length)
{
    return ((stra->length==length) && (memcmp(stra->str, data, length)==0)) ? 1 : 0;
}

int str_read_string_hlpr(struct ssh_str_s *data, struct ssh_str_s *value)
{
    uint32_t length = read_ssh_str(data->str, data->length, value);

    if ((value->flags & SSH_STRING_FLAG_INVALID)==0) {

        data->length -= length;
        data->str += length;
        return 1;

    }

    return 0;
}

int str_read_uint32_hlpr(struct ssh_str_s *data, uint32_t *p_value)
{

    if (data->str && (data->length>=4)) {

        if (p_value) *p_value=get_uint32(data->str);
        data->str+=4;
        data->length-=4;
        return 1;

    }

    return 0;

}
