/* ost_ipcache.c - Recording of IP addresses, lockout of attackers.
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
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <arpa/inet.h>
#include <string.h>

#include "ost.h"
#include "ost_globals.h"
#include "ost_debug.h"
#include "ost_ipcache.h"
#include "ost_runcmd.h"

/* Only loop through existing entries. */
#define NEXT_READ_ELEM(x) (x==s_cur_ipcache_max?0:x+1)
/* Loop through 'em all. */
#define NEXT_WRITE_ELEM(x) (x==MAX_NUM_CACHED_IPS-1?0:x+1)

/* Don't need to be global, so limit 'em to this module. */
int s_cur_ipcache_max;   /* How many items in the cache. */
int s_cur_ipcache_write; /* Where to start looking to add an ip. */
int s_read_addr;         /* Where to start looking to find an ip. */

/* The actual cache. */
OST_ip_cache_elem_t s_ip_cache[MAX_NUM_CACHED_IPS];

/* Uses a caching strategy variously called "FINUFO" (First In
   Not Used First Out), also called a 'clock' or 'lookaside'
   cache. This has quite good performance over a wide range of
   inputs.
   Basically, we set a flag when a field is used. We 'look aside'
   from that field the next time we want to add something to the
   cache, but we clear the flag. This works surprisingly well at
   keeping frequently-used items in the cache, and is simple to
   implement. */

/* See if we've passed any of the error thresholds.
   If so, exit the program. */
void Check_Errors(int single_count, struct in_addr addr)
{
  /* Check to see if we've passed the 'single' threshold. */
  if (g_max_single_errors &&
      single_count > g_max_single_errors) {
    Log_Message(LOG_CRIT,
                "IP '%s' exceeded single-IP threshold %d, exiting!\n",
                inet_ntoa(addr), g_max_single_errors);
    exit(EXIT_SUCCESS);
  }

  /* Check to see if we've passed the 'total' threshold.
     Note we only increment 'g_total_errors' if we're actually
     checking for them. */
  if (g_max_total_errors &&
      ++g_total_errors > g_max_total_errors) {
    Log_Message(LOG_CRIT,
                "IP '%s' exceeded total threshold %d, exiting!\n",
                inet_ntoa(addr), g_max_total_errors);
    exit(EXIT_SUCCESS);
  }
}

/* Clear everything out. */
void Init_Ip_Cache()
{
  s_cur_ipcache_max = s_cur_ipcache_write = s_read_addr = 0;
  memset(s_ip_cache, 0, MAX_NUM_CACHED_IPS*sizeof(OST_ip_cache_elem_t));
}

/* Returns nonzero if an IP is stored in the cache and has too
   many bad connections, zero otherwise. Starts searching from
   where the last search ended up. If 'clear' is nonzero and the
   address is found, its connection count is reset. */
int Check_Addr_Against_Cache(struct in_addr clnt_addr, int clear)
{
  int i;

  i = s_read_addr;
  do {
    if (s_ip_cache[i].ipaddr.s_addr == clnt_addr.s_addr) {
      Log_Message(LOG_DEBUG, "Found addr at position %d.\n", i);
      s_read_addr = i; /* Start search here next time. */
      if (clear) {
        Log_Message(LOG_DEBUG, "IP addr '%s' cleared.\n",
                    inet_ntoa(clnt_addr));
        s_ip_cache[i].conn_count = 0; /* successful command */
        return 0;
      } else {
        s_ip_cache[i].inuse = -1; /* Mark it as used recently. */
        if (s_ip_cache[i].conn_count >= g_max_bad_conns) {
          s_ip_cache[i].conn_count++;
          Log_Message(LOG_NOTICE, "IP addr is locked, has %d bad attempts.\n",
                    s_ip_cache[i].conn_count);

          /* See if we've passed any of the error thresholds. */
          Check_Errors(s_ip_cache[i].conn_count, clnt_addr);

          return -1;
        } else {
          Log_Message(LOG_NOTICE,
                      "IP addr not locked yet, has %d bad attempts.\n",
                    s_ip_cache[i].conn_count);
          return 0;
        }
      }
    }
  } while ((i = NEXT_READ_ELEM(i)) != s_read_addr);

  /* Not in the cache. Accept for now. */
  return 0;
}

/* If the input IP is in the cache, increment its count. If not,
   add it to the cache. */
void Add_Or_Update_IP(struct in_addr clnt_addr)
{
  int i;

  /* First, check to see if it's already in cache. */
  i = s_read_addr;
  do {
    assert(i<MAX_NUM_CACHED_IPS);
    if (s_ip_cache[i].ipaddr.s_addr == clnt_addr.s_addr) {
      /* Found it! */
      s_read_addr = i; /* Start search here next time. */
      s_ip_cache[i].conn_count++; /* More strikes... */

      s_ip_cache[i].inuse = -1; /* Might be useful. */
      Log_Message(LOG_NOTICE, "IP count updated, has %d bad attempts.\n",
                   s_ip_cache[i].conn_count);

      if (s_ip_cache[i].conn_count == g_max_bad_conns) {
        /* We have just locked out this address. If the user configured
           a command, call a script. */
        Log_Message(LOG_NOTICE, "IP address locked out!\n");
        if (g_lockout_action.command[0]) {
          /* There's something in the command string. Run it. */
          if (Run_Command(g_lockout_action.command,
                          clnt_addr,
                          g_lockout_action.new_uid,
                          g_lockout_action.new_gid)) {
            Log_Message(LOG_ERR, "Error running lockout cmd '%s'!\n",
                        g_command_table[i].command);
          }
        }
      }

      /* Check to see if we've passed any global thresholds. */
      Check_Errors(s_ip_cache[i].conn_count, clnt_addr);

      return; /* All done. */
    }
  } while ((i = NEXT_READ_ELEM(i)) != s_read_addr);

  Log_Message(LOG_NOTICE, "IP '%s' not in cache, adding.\n",
            inet_ntoa(clnt_addr));
  /* Not in the cache. Add it. Note: if an element is inuse, we
     clear the inuse flag. One way or another, we WILL encounter
     a field not in use, even if we have to loop all the way around
     the cache and clear every inuse flag first. */
  for (i = s_cur_ipcache_write; 1 /* always true */; i = NEXT_WRITE_ELEM(i)) {
    assert(i<MAX_NUM_CACHED_IPS);
    if (!s_ip_cache[i].inuse) {
      Log_Message(LOG_DEBUG, "Adding IP to position %d.\n", i);
      /* Cool, we can stick it here. */
      s_ip_cache[i].conn_count = 1; /* One strike already. */
      s_ip_cache[i].inuse = 0;
      s_ip_cache[i].ipaddr = clnt_addr;
      s_cur_ipcache_write = NEXT_WRITE_ELEM(i);
      s_read_addr = i; /* Start search here next time. */

      /* Keep track of size of cache. */
      if (s_cur_ipcache_max == MAX_NUM_CACHED_IPS-1) {
        if (g_exit_on_cache_full) {
          Log_Message(LOG_CRIT, "Cache full, exiting program!\n");
          exit(EXIT_SUCCESS);
        }
        Log_Message(LOG_NOTICE, "Cache maxed out, '%d'\n", s_cur_ipcache_max);
      } else {
        s_cur_ipcache_max++;
        Log_Message(LOG_DEBUG,"Cache contains %d ips.\n", s_cur_ipcache_max);
      }

      /* See if we've passed any of the error thresholds.
         (I doubt if anyone would really set them to '1', but... */
      Check_Errors(s_ip_cache[i].conn_count, clnt_addr);

      return;
    }
    /* Mark it as clear. */
    s_ip_cache[i].inuse = 0;
  }
}
