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

#ifndef STR_UTILS_H
#define STR_UTILS_H

#define SSH_STRING_FLAG_INVALID                         1
#define SSH_STRING_INIT                                 {0, NULL, 0}

struct ssh_str_s {
    uint32_t                                            length;
    char                                                *str;
    unsigned int                                        flags;
};

/* prototypes */

void init_ssh_string(struct ssh_str_s *str);
uint32_t get_uint32(char *buf);
unsigned int read_ssh_str(char *buffer, unsigned int size, struct ssh_str_s *str);
int cmp_ssh_str(struct ssh_str_s *stra, char *data, unsigned int length);

int str_read_string_hlpr(struct ssh_str_s *data, struct ssh_str_s *value);
int str_read_uint32_hlpr(struct ssh_str_s *data, uint32_t *p_value);

#endif
