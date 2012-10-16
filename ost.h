/* ost.h - Declaration of defaults, overall limits and data structures.
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
#ifndef _OST_H_
#define _OST_H_

#ifdef WIN32
/* Only the defines needed for the client... */
/* Note: strictly IPv4 for now... */
#define MAX_SIZEOF_IP 16

#define MAX_NUM_SECRETS 8
#define MAX_NUM_CACHED_IPS 128

#define MAX_SECRET_SIZE 64
#define MAX_PATHNAME_SIZE 128
#define MAX_COMMAND_SIZE 128

#define LINEBUF_SIZE 512

#else /* WIN32 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>

/* #ifdef OST_VMS
#include <in.h>
#include <unixio.h>
#else */
#include <netinet/in.h>
#include <unistd.h>
/*#endif*/

/* Compile-time limits */

/* Note: strictly IPv4 for now... */
#define MAX_SIZEOF_IP 16

#define MAX_NUM_SECRETS 8
#define MAX_NUM_CACHED_IPS 128

/* You can make MAX_SECRET_SIZE bigger, but don't forget to update
   the clients! Also, it's not a good idea to make it less than
   HASH_BIN_SIZE. */
#define MAX_SECRET_SIZE 64
#define MAX_PATHNAME_SIZE 128
#define MAX_COMMAND_SIZE 128

#define LINEBUF_SIZE 512

/* Default values for various config options. */
#define DEFAULT_USERNAME "nobody"

/* This macro magic is needed to turn an unquoted #define into a quoted
   string to pass as an argument to a function. */
#define EXPAND_DEF_TO_STR(s) MAKE_STR(s)
#define MAKE_STR(s) #s

#define DEFAULT_CFGFILE_NAME "/ostiary.cfg"

#define DEFAULT_CONNECT_DELAY 5
#define DEFAULT_MAX_BAD_CONNS 3
#define DEFAULT_COMM_TIMEOUT 5

typedef struct OST_CMDLINE_OPTS_T {
  unsigned short connect_delay;
  unsigned short port;
  unsigned short ignore_urandom;
  unsigned short local_ip_set; /* flag to determine if IP set on cmdline */
  struct in_addr local_ip;
} OST_cmdline_opts_t;

/* The possible types of cfgvars. */
typedef enum OST_CFGVAR_TYPES {
  OST_VOID=0,
  OST_TOGGLE,  /* No arguments, just set boolean. */
  OST_SHORT,
  OST_INT, /* Currently unused. */
  OST_LOGLEVEL, /* Man syslog(3) */
  OST_ID,      /* User/Group IDs */
  OST_IP_ADDR, /* IP Addresses */
  OST_STRING,  /* file paths, etc. */
  OST_ACTION   /* commands and associated secrets */
} OST_cfgvar_types;

typedef struct OST_IP_CACHE_ELEM_T {
  short inuse; /* used for lookaside ('clock') cache; could be a char
                or even just a bit, but I'm willing to trade memory
                for speed, aligment, and simplicity. */
  unsigned short conn_count; /* Count of how many times this IP's
                       failed a connection.
                       Assuming minimum 5 second delay, someone could
                       theoretically overflow this after 91 hours, but
                       if they've got that much patience I figure they've
                       earned another shot at cracking the password. At
                       one try every 3.8 days, they have a negligible
                       chance of success before Sol burns out. Much easier
                       to dictionary-attack a captured packet. */
  struct in_addr ipaddr; /* the client address */ 
} OST_ip_cache_elem_t;

typedef struct OST_CMDTABLE_ELEM_T {
  uid_t new_uid;
  gid_t new_gid;
  char secret[MAX_SECRET_SIZE];
  char command[MAX_COMMAND_SIZE];
} OST_cmdtable_elem_t;

typedef struct OST_CFGPARAM_ELEM {
  char *param_name;
  OST_cfgvar_types elemtype;
  size_t data_size; /* mostly used for strings */
  void *param_ptr;
} OST_cfgparam_elem;

#endif /* WIN32 */

/* Needed anywhere we might exit. */
void Clear_Password_Memory();

#endif /* _OST_H_ */
