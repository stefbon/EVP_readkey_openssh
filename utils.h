/*
  2017, 2018 Stef Bon <stefbon@gmail.com>

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

*/

#ifndef UTILS_H
#define UTILS_H

#include "str-utils.h"

#define UTILS_READ_FILE_FLAG_RESET_FILEPOS                      1
#define UTILS_READ_FILE_FLAG_EOF                                2
#define UTILS_READ_FILE_FLAG_FREE_BUFFER                        4

struct utils_buffer_s {
    unsigned int                                                flags;
    char                                                        *ptr;
    unsigned int                                                size;
    unsigned int                                                length;
};

#define UTILS_BUFFER_INIT                                       {0, NULL, 0, 0}

/* prototypes */

void UTILS_init_buffer(struct utils_buffer_s *buffer, char *data, unsigned int size);
void UTILS_free_buffer(struct utils_buffer_s *buffer);

unsigned int UTILS_read_file(BIO *file, struct utils_buffer_s *buffer, unsigned int size, int (* cb_read)(struct utils_buffer_s *buffer, void *ptr), void *ptr, unsigned int flags);
unsigned int UTILS_read_whole_file(BIO *file, struct utils_buffer_s *buffer, unsigned int size);

#endif
