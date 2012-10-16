/* ost_hash.c - Implementation of hashing.
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

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "sha-256.h"

#include "ost.h"
#include "ost_hash.h"

/* Everything to do with hashing is concentrated here and in ost_hash.h.
   This way we can replace the hash function and hopefully not have to
   touch any other code. To do this, you need to set the constants in
   ost_hash.h (HASH_BIN_SIZE and HASH_BLOCK_SIZE) to the correct values
   for the new hash function, and change the calls below to sha256_buffer()
   to instead call the new hash function. HMAC per se doesn't care about
   the details of the hash function it uses. */

void Print_Hash(unsigned char *hash, char *out_buf, size_t out_len)
{
  int i;

  assert(out_len >= HASH_BIN_SIZE*2+1);

  memset(out_buf, 0, out_len);

  for (i=0; i<HASH_BIN_SIZE; i++) {
    sprintf(out_buf+(i*2), "%02x", hash[i]);
  }
}

/* The old version-1 and version-2 hashes have been removed and are
   strongly deprecated. Vanilla MD5 just can't be trusted at this point. */

/* The version 4 hash. Essentially identical to the version 3 hash,
   except using SHA-256 instead of SHA1. Note that this means the hash
   is 32 bytes (256 bits) instead of 20 bytes (160 bits). */
void Do_Ostiary_Hash(unsigned char *in_hash, size_t in_hash_siz,
             char *secret, size_t secret_siz, unsigned char *hash_out)
{
  int i;
  char temp_hash[HASH_BIN_SIZE]; /* only needed if secret's too big */
  char hash_input[HASH_INPUT_SIZE];

  assert(secret_siz < MAX_SECRET_SIZE);

  /* Clear the input struct. */
  memset(hash_input, 0, HASH_INPUT_SIZE);

  /* Load up the secret. */
  if (secret_siz < HASH_BLOCK_SIZE) {
    memcpy(hash_input, secret, secret_siz);
  } else {
    /* Too big, just store the hash, per the HMAC spec. */
    /* Note: currently this just can't happen, but if someone mucks with
       the max secret size, or changes hash functions, this won't break. */
    sha256_buffer(secret, secret_siz, temp_hash);
    memcpy(hash_input, temp_hash, HASH_BIN_SIZE);
  }

  /* XOR the first block with the inner pad value. */
  for (i=0; i<HASH_BLOCK_SIZE; i++) {
    hash_input[i] ^= 0x36;
  }

  /* Now add the salt from the server. */
  memcpy(hash_input+HASH_BLOCK_SIZE, in_hash, in_hash_siz);

  /* The first (inner) hash. Note we use the 'hash_out' buffer as
     temporary storage for the inner hash. */
  sha256_buffer(hash_input, HASH_BLOCK_SIZE+in_hash_siz, hash_out);

  /* Now the outer hash. */

  /* Clear the input struct again. */
  memset(hash_input, 0, HASH_INPUT_SIZE);

  /* Copy the secret again. */
  if (secret_siz < HASH_BLOCK_SIZE) {
    memcpy(hash_input, secret, secret_siz);
  } else {
    /* Too big, just store the hash, per the HMAC spec. */
    /* (temp_hash already computed above) */
    memcpy(hash_input, temp_hash, HASH_BIN_SIZE);
  }

  /* The outer pad XOR value. */
  for (i=0; i<HASH_BLOCK_SIZE; i++) {
    hash_input[i] ^= 0x5c;
  }

  /* Append the inner hash. */
  memcpy(hash_input+HASH_BLOCK_SIZE, hash_out, HASH_BIN_SIZE);

  /* The second (outer) hash. */
  sha256_buffer(hash_input, HASH_BLOCK_SIZE+HASH_BIN_SIZE , hash_out);

  /* All done! */
}
