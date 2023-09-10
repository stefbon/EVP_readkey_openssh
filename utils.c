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

void UTILS_init_buffer(struct utils_buffer_s *buffer, char *data, unsigned int size)
{
    buffer->ptr=NULL;
    buffer->size=0;
    buffer->length=0;
    buffer->flags=0;
}

void UTILS_free_buffer(struct utils_buffer_s *buffer)
{
    if (buffer->ptr) free(buffer->ptr);
    UTILS_init_buffer(buffer, NULL, 0);
}

unsigned int UTILS_read_file(BIO *file, struct utils_buffer_s *buffer, unsigned int size, int (* cb_read)(struct utils_buffer_s *buffer, void *ptr), void *ptr, unsigned int flags)
{
    int filepos2keep=BIO_tell(file);
    unsigned int length2keep=0;
    char *data=NULL;
    int result=0;

    if (buffer==NULL || file==NULL || cb_read==NULL) {

        fprintf(stdout, "invalid parameters.\n");
        return 0;

    }

    if (size==0) size=512;

    readline:

    buffer->ptr=realloc(buffer->ptr, size);
    if (buffer->ptr==NULL) {

        fprintf(stdout, "not able to allocate %u bytes.\n", size);
        goto errorout;

    }

    buffer->size=size;
    memset(buffer->ptr, 0, size);
    result=BIO_read(file, buffer->ptr, size);

    if (result==0 || result==-1) {

        fprintf(stdout, "not able to read %u bytes from file.\n", size);
        goto errorout;

    }

    buffer->length=(unsigned int) result;
    if (BIO_eof(file)) buffer->flags |= UTILS_READ_FILE_FLAG_EOF;
    length2keep=buffer->length;

    /* stop if a newline is found or the whole file is read */

    result=cb_read(buffer, ptr);

    if (result==-1) {

        goto errorout;

    } else if ((result==0) && ((buffer->flags & UTILS_READ_FILE_FLAG_EOF)==0)) {

        size+=512;
        BIO_seek(file, filepos2keep);
        goto readline;

    }

    fprintf(stdout, "%s: %u bytes read result %i.\n", __FUNCTION__, buffer->length, result);

    out:

    if (flags & UTILS_READ_FILE_FLAG_RESET_FILEPOS) {

        BIO_seek(file, filepos2keep);

    } else {

        /* if length of buffer has been changed (by cb) adjust the file position to that value */

        if (buffer->length < length2keep) BIO_seek(file, buffer->length);

    }

    if (flags & UTILS_READ_FILE_FLAG_FREE_BUFFER) UTILS_free_buffer(buffer);
    return (unsigned int) result;

    errorout:

    if (flags & UTILS_READ_FILE_FLAG_RESET_FILEPOS) BIO_seek(file, filepos2keep);
    UTILS_free_buffer(buffer);
    return 0;

}

static int cb_read_whole_file(struct utils_buffer_s *buffer, void *ptr)
{
    return ((buffer->flags & UTILS_READ_FILE_FLAG_EOF) ? 1 : 0);
}

unsigned int UTILS_read_whole_file(BIO *file, struct utils_buffer_s *buffer, unsigned int size)
{
    return UTILS_read_file(file, buffer, size, cb_read_whole_file, NULL, UTILS_READ_FILE_FLAG_RESET_FILEPOS);
}
