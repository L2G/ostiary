/* sha-256.h - Declaration of functions and data types used for SHA-256 sum
   computing library functions.
   Copyright (C) 2010 Raymond Ingles
*/

#ifndef _SHA_256_H
#define _SHA_256_H 1

/* Compute SHA-256 message digest for LEN bytes beginning at BUFFER.  The
   result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */
extern void *sha256_buffer (const char *buffer, size_t len, void *resblock);

#endif
