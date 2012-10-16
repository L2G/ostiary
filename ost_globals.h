/* ost_runcmd.h - Declaration of OST daemon global variables.
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
#ifndef _OST_GLOBALS_H_
#define _OST_GLOBALS_H_

#include <stdio.h>

extern uid_t g_default_uid;
extern gid_t g_default_gid;
extern unsigned short g_time_window;
extern unsigned short g_connect_delay;
extern unsigned short g_connect_timeout;
extern unsigned short g_max_bad_conns;
extern unsigned short g_max_seq_secrets;
extern unsigned short g_verboseness;
extern unsigned short g_exit_on_cache_full;
extern unsigned short g_port;
extern struct in_addr g_local_ip;
extern unsigned short g_total_errors;
extern unsigned short g_max_total_errors;
extern unsigned short g_max_single_errors;
extern unsigned short g_sighup_flag;
extern unsigned short g_current_action;

extern OST_cmdtable_elem_t g_command_table[MAX_NUM_SECRETS];
extern OST_cmdtable_elem_t g_lockout_action;
extern char g_logfile_path[MAX_PATHNAME_SIZE];
extern char g_kill_secret[MAX_SECRET_SIZE];
extern char g_sequence_secrets[MAX_NUM_SECRETS][MAX_SECRET_SIZE];

extern OST_cfgparam_elem g_param_table[];

#endif /* _OST_GLOBALS_H_ */
