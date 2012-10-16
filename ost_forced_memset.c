/* ost_forced_memset.c - Guarantees clearing of memory with passwords.
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

/* Some compilers optimize away memset()s that don't end up being used
   later. This uses the 'volatile' keyword to make damn sure the memory
   is actually cleared out. */
#include "ost_forced_memset.h"

#ifdef WIN32
void *forced_memset(void *v, int c, int n)
#else
void *forced_memset(void *v, int c, size_t n)
#endif
{
  volatile char *p=v;
  while (n--) {
    *p++=c;
  }
  return v;
}
