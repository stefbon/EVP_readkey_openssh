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

#ifndef OPENSSH_UTILS_H
#define OPENSSH_UTILS_H

#include "str-utils.h"

#define PKEY_FILE_HEADER_OPENSSH_PRIVATE                                1
#define PKEY_FILE_HEADER_RSA_PRIVATE                                    2

/* prototypes */

int OPENSSH_read_openssh_key(struct ssh_str_s *data, struct ssh_key_param_s *key, const char *algorithm);
int OPENSSH_read_openssh_format_data(EVP_PKEY **p_pkey, struct utils_buffer_s *buffer, unsigned int formatcode, unsigned char secret, struct ssh_algorithm_s *guessed);

int OPENSSH_read_public_key_data(EVP_PKEY **p_pkey, struct ssh_str_s *data, struct ssh_algorithm_s *found);
int OPENSSH_read_public_key_fileline(EVP_PKEY **p_pkey, BIO *file, struct ssh_algorithm_s *guessed, unsigned char algoread);

unsigned int OPENSSH_check_format(BIO *file, struct utils_buffer_s *buffer);

#endif
