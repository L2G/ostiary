/* ost_hash.h - Declaration of functions and data types used for hash
   computation.
   Copyright (C) 2003 Raymond Ingles.

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 2, or (at your option) any
   later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */
#ifndef _OST_HASH_H_
#define _OST_HASH_H_

/* The size in bytes of the hash output. */
#define HASH_BIN_SIZE 32
/* The size in bytes of the block the hash operates on. */
#define HASH_BLOCK_SIZE 64
#define HASH_TEXT_SIZE (HASH_BIN_SIZE*2+1)
#define HASH_INPUT_SIZE (HASH_BLOCK_SIZE+HASH_BIN_SIZE)

void Print_Hash(unsigned char *hash, char *out_buf, size_t out_len);
void Do_Ostiary_Hash(unsigned char *in_hash, size_t in_hash_siz,
             char *secret, size_t secret_siz, unsigned char *hash_out);

#endif /* _OST_HASH_H_ */
