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

#ifndef EVP_utils_h
#define EVP_utils_h

/* prototypes */

int EVP_decodeinplace(struct ssh_str_s *data, unsigned char r);

struct ssh_algorithm_s *get_ssh_algorithm_by_name(char *name);
struct ssh_algorithm_s *get_ssh_algorithm_by_filename(char *filename, unsigned char *p_secret);

struct ssh_algorithm_s *BIO_read_ssh_algorithm(BIO *file, char *buffer, unsigned int size);

int EVP_PKEY_fromparams(EVP_PKEY **p_pkey, const char *type, int selection, OSSL_PARAM param[]);
int EVP_PKEY_read_ssh_key_param(EVP_PKEY **p_pkey, struct ssh_key_param_s *key, unsigned char secret);
int EVP_PKEY_read_with_decoder(EVP_PKEY **p_pkey, BIO *fpkey, char *name, unsigned char secret);

#endif
