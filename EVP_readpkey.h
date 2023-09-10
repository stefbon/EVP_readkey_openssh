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

#ifndef EVP_readpkey_H
#define EVP_readpkey_H

struct ssh_algorithm_s {
    const char                                  *name;
    const char                                  *filename;
    unsigned int                                minlength;
};

struct ssh_key_param_s {
    unsigned int                                version;
    const char                                  *algoname;
    union _ssh_key_u {
        struct _ssh_key_rsa_s {
            struct ssh_str_s                    e;
            struct ssh_str_s                    n;
            struct ssh_str_s                    d;
            struct ssh_str_s                    iqmp;
            struct ssh_str_s                    p;
            struct ssh_str_s                    q;
            struct ssh_str_s                    comment;
        } rsa;
        struct _ssh_key_ed25519_s {
            struct ssh_str_s                    q;
            struct ssh_str_s                    d;
            struct ssh_str_s                    comment;
        } ed25519;
    } data;
};

/* prototypes */

#endif
