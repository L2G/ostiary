/* ost_main.c - Implementation of OST daemon.
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
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <unistd.h>
#include <signal.h>

#include <sys/mman.h> /* mlock() */
#if HAVE_LIBWRAP
#include <tcpd.h>
#endif

#if HAVE_LIBGEN_H
#include <libgen.h>
#endif

#if TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "ost.h"
#include "ost_debug.h"
#include "ost_hash.h"
#include "ost_cfgparse.h"
#include "ost_ipcache.h"
#include "ost_runcmd.h"
#include "ost_forced_memset.h"

#if HAVE_LIBWRAP
int allow_severity;
int deny_severity;
#endif

/* Global vars */
struct in_addr g_local_ip;
pid_t g_my_pid;
uid_t g_default_uid;
gid_t g_default_gid;
int g_randfile;
unsigned short g_total_errors;
/* Various config options. */
unsigned short g_exit_on_cache_full;
unsigned short g_port;
unsigned short g_max_bad_conns;
unsigned short g_connect_delay;
unsigned short g_comm_timeout;
unsigned short g_ignore_urandom;
unsigned short g_skip_detach;
unsigned short g_max_total_errors;
unsigned short g_max_single_errors;
unsigned short g_sighup_flag;
unsigned short g_current_action; /* used in cfg parsing; used to store
                                    this in the param_table, but that
                                    can't be cleanly reinitialized. */

OST_cmdtable_elem_t g_command_table[MAX_NUM_SECRETS];
OST_cmdtable_elem_t g_lockout_action;
char g_kill_secret[MAX_SECRET_SIZE];

char g_cfgfile_path[MAX_PATHNAME_SIZE];

/* Where the PIDfile should be. */
char g_pidfile_name[MAX_PATHNAME_SIZE];

/* Define the possible config-file parameters and the variables
   they control. Must terminate this table with NULL values. */
OST_cfgparam_elem g_param_table[] = {
  {"EXIT_ON_IPCACHE_FULL", OST_TOGGLE, sizeof(g_exit_on_cache_full),
                                                 &g_exit_on_cache_full},
  {"IGNORE_URANDOM", OST_TOGGLE, sizeof(g_ignore_urandom),
                                                 &g_ignore_urandom},
  {"SKIP_DETACH", OST_TOGGLE, sizeof(g_skip_detach),
                                                 &g_skip_detach},
  {"PORT", OST_SHORT, sizeof(g_port), &g_port},
  {"MAX_BAD_CONNS", OST_SHORT, sizeof(g_max_bad_conns), &g_max_bad_conns},
  {"MAX_TOTAL_ERRS", OST_SHORT, sizeof(g_max_total_errors),
                                                 &g_max_total_errors},
  {"MAX_SINGLE_ERRS", OST_SHORT, sizeof(g_max_single_errors),
                                                 &g_max_single_errors},
  {"DELAY", OST_SHORT, sizeof(g_connect_delay), &g_connect_delay},
  {"COMM_TIMEOUT", OST_SHORT, sizeof(g_comm_timeout), &g_comm_timeout},
  {"MIN_LOGLEVEL", OST_LOGLEVEL, 0, NULL},
  {"DEFAULT_UID", OST_ID, MAX_PATHNAME_SIZE, &g_default_uid},
  {"DEFAULT_GID", OST_ID, MAX_PATHNAME_SIZE, &g_default_gid},
  {"LOCAL_IP", OST_IP_ADDR, sizeof(g_local_ip), &g_local_ip},
  {"KILL", OST_STRING, MAX_SECRET_SIZE, g_kill_secret},
  {"PIDFILE", OST_STRING, MAX_PATHNAME_SIZE, g_pidfile_name},
  {"ACTION", OST_ACTION, 0, g_command_table},
  {"LOCKOUT_ACTION", OST_ACTION, 1, &g_lockout_action},
  {NULL, OST_VOID, 0, NULL}
};

/* Try the one compiled-in at make time, and a bunch of other
   possible locations. */
char *g_cfg_paths[] = { EXPAND_DEF_TO_STR (SYSCONFDIR),
                        "/etc", "/etc/ostiary", "/etc/opt",
                        "/usr/etc", "usr/etc/ostiary",
                        "/etc/opt/ostiary", "/usr/local/etc",
                        "/usr/local/etc/ostiary", "/usr/local/ostiary",
                        NULL };

/* Use regular Unix getopt. */
extern char *optarg;
extern int optind, opterr, optopt;

int Get_Cmdline_Options(int argc, char *argv[],
                        OST_cmdline_opts_t *cmdline_opts)
{
  /* Use getopt(), set up any non-default values. */
  int c, error=0;
  int c_found = 0, d_found = 0, s_found = 0, i_found = 0, p_found = 0,
    r_found = 0, D_found=0;

  /* Initialize cfg file name. */

  while (EOF != (c = getopt(argc, argv, "c:d:s:i:p:vrD"))) {
    switch (c) {
    case 'c':
      if (c_found) {
        /* Hey! We already did this option! */ 
        error = 1;
      } else {
        /* Okay, we've got a config file. */
        c_found = 1;
        strncpy(g_cfgfile_path, optarg, MAX_PATHNAME_SIZE-1);
      }
      break;
    case 'd': 
      if (d_found) {
        /* Hey! We already did this option! */
        error = 1;
      } else {
        cmdline_opts->connect_delay = atoi(optarg);
        d_found = 1;
      }
      break;
    case 's': 
      if (s_found) {
        /* Hey! We already did this option! */
        error = 1;
      } else {
        srandom(atoi(optarg));
        s_found = 1;
      }
      break;
    case 'p': 
      if (p_found) {
        /* Hey! We already did this option! */
        error = 1;
      } else {
        cmdline_opts->port = atoi(optarg);
        p_found = 1;
      }
      break;
    case 'i': 
      if (i_found) {
        /* Hey! We already did this option! */
        error = 1;
      } else {
        if (!inet_aton(optarg, &(cmdline_opts->local_ip))) {
          error = 1;
        }
        i_found = cmdline_opts->local_ip_set = 1;
      }
      break;
    case 'r': 
      if (r_found) {
        /* Hey! We already did this option! */
        error = 1;
      } else {
        cmdline_opts->ignore_urandom = 1;
        r_found = 1;
        if (optarg) {
          error = 1; /* this shouldn't have an arg. */
        }
      }
      break;
    case 'D': 
      if (D_found) {
        /* Hey! We already did this option! */
        error = 1;
      } else {
        g_skip_detach = 1;
        D_found = 1;
        if (optarg) {
          error = 1; /* this shouldn't have an arg. */
        }
      }
      break;
    case 'v':
      Set_Log_Level(LOG_INFO); /* Become rather chatty. */
      if (optarg) {
        error = 1; /* this shouldn't have an arg. */
      }
      break;
    case '?':
    case 'h':
    default:
      error = 1; /* something's wrong. */
      break;
    }
    if (error) {
      /* Some kind of command line error. */
      printf("usage: %s [options]\n"
             "\t-c\tconfig file\n"
             "\t-d\tconnect delay, in seconds\n"
             "\t-s\trandom seed\n\t-p\tlisten port\n\t-i\tlisten IP addr\n"
             "\t-r\t(ignore /dev/urandom)\n\t-v\t(verbose)\n"
             "\t-D\t(don't detach)\n",
             argv[0]);
      return -1;
    }
  }
  return 0; /* All's well that ends well */
}

/* Set up the default IDs to run commands as. */
void Set_Default_IDs(void)
{
  uid_t cur_uid;
  struct passwd *nobdy;

  if ((cur_uid = getuid())) {
    /* We're not running as root. Set scripts to run as us. */
      g_default_uid = cur_uid;
      g_default_gid = getgid();
      return;
  }

  /* Okay, we're running as root. Set the default. */
  if (NULL == (nobdy = getpwnam(DEFAULT_USERNAME))) {
    Log_Message(LOG_WARNING, "User '%s' not available, defaulting to root!\n",
               DEFAULT_USERNAME);
  } else {
    Log_Message(LOG_NOTICE, "Default uid=%d, default gid=%d.\n",
                nobdy->pw_uid, nobdy->pw_gid);
    g_default_uid = nobdy->pw_uid;
    g_default_gid = nobdy->pw_gid;
  }
}

/* Run detatched, set up file descriptors, etc. */
int Daemonize()
{
  pid_t pid;
  char temppath[MAX_PATHNAME_SIZE];

  /* Protect any files we make. */
  umask(027);

  /* Needed if Ostiary is run from inetd or as a Cygwin service. */
  if (g_skip_detach) {
    return 0;
  }

  /* First, we close the standard file descriptors. */
  for (pid=2; pid>=0; pid--) {
    close(pid);
  }

  /* Point the standard file descriptors (stdout, stdin, stderr)
     at something safe. This is more for our children than ourselves.
     Ostiaryd itself doesn't really do anything with 'em, so it's
     okay to ignore return values here. */
  pid=open("/dev/null", O_RDWR); /* open stdin */
  dup(pid); /* stdout */
  dup(pid); /* stderr */

  /* Now, we detach from the start proc and become a child of init. */
  if (0>(pid=fork())) {
    /* Fork error! */
    return -1;
  }
  if (pid) {
    /* We're the parent. Bye-bye. */
    exit(EXIT_SUCCESS);
  }

  /* Detach from controlling tty. */
  setsid();

  /* This way any filesystems we were started with can be unmounted,
     except the one that contains our config file.
     We ignore errors, because there's no reasonable way to handle
     such a failure. */
#if HAVE_DIRNAME
  memcpy(temppath, g_cfgfile_path, strlen(g_cfgfile_path));
  /* dirname() may change the input string, so we have to use this copy. */
  if (-1 == chdir(dirname(temppath))) {
    Log_Message(LOG_NOTICE, "Could not chdir to '%s': %m!", g_cfgfile_path);
  }
#else
  chdir("/");
#endif

  /* All done. */
  return 0;
}

/* Clean up PID file. */
void Remove_PID_File()
{
  /* The name, if set at all, includes a path and everything.
     We don't really worry about errors 'cause there isn't a lot
     we could do about them at this point. */
  if (g_pidfile_name[0]) {
    Log_Message(LOG_INFO, "Removing pidfile '%s'.", g_pidfile_name);
    unlink(g_pidfile_name);
  }
}

/* Create a PIDfile, if possible. */
void Create_PID_File()
{
  int pidfiled;
  char pid_buf[12]; /* Enough for 32-bit PIDs */

  memset(pid_buf, 0, sizeof(pid_buf));
  if (g_pidfile_name[0]) {
    /* Remove any stale ones, if they exist. */
    Remove_PID_File();

    Log_Message(LOG_INFO, "Creating pidfile '%s'.", g_pidfile_name);

    /* Create the new file for writing, permissions set to read-only. */
    if (-1 == (pidfiled = open(g_pidfile_name, O_WRONLY | O_CREAT | O_TRUNC,
                    S_IRUSR | S_IRGRP | S_IROTH))) {
      Log_Message(LOG_ERR, "Could not create pidfile '%s': %m!",
                  g_pidfile_name);
      return;
    }

    /* Write out our PID. */
    g_my_pid = getpid();
    sprintf(pid_buf, "%d\n", g_my_pid);
    if (-1 == write(pidfiled, pid_buf, strlen(pid_buf))) {
      Log_Message(LOG_ERR, "Could not write '%d' to pidfile '%s': %m!",
                  g_my_pid, g_pidfile_name);
    }

    /* All done. */
    close(pidfiled);
  } else {
    Log_Message(LOG_INFO, "No pidfile specified.");
  }
}

/* Initialize the variables and parameters, using the command-line
   options, the config file, and the defaults, in that order of
   priority. Several things are skipped if we are reinitializing. */
int OST_Init(int argc, char *argv[],
             int *listen_sock, struct sockaddr_in *listen_addr, int first)
{
  int i;
  struct rlimit rl;
  OST_cmdline_opts_t cmdline_opts;

  if (first) {
    /* Don't allow us to produce a core file. Passwords might be
       leaked there. */
    rl.rlim_cur=0;
    rl.rlim_max=0;
    setrlimit(RLIMIT_CORE, &rl);
  } else {
    /* We're reinitializing. Close our existing socket, and the log
       file.*/
    close(*listen_sock);
    Close_Log_File();
  }

  Open_Log_File("ostiaryd");
  Set_Log_Level(LOG_NOTICE); /* Log the basics+errors. */

  /* These must be reset every time we initialize, whether the first
     time or from a SIGHUP. */
  g_current_action = 0;
  memset(g_command_table, 0, MAX_NUM_SECRETS*sizeof(OST_cmdtable_elem_t));
  memset(g_kill_secret, 0, MAX_SECRET_SIZE);

  /* Clear all the other vars if needed. */
  if (first) {
#if HAVE_MLOCK
    /* Lock the memory containing passwords so it can't be swapped. We
       only lock about 1.5K, so on any architecture I'm aware of, at
       worst we might lock two pages if the structs cross a page boundary.
       On Intel, this is only about 8K. If you can't live with that,
       comment this section out.

       If we're not running as root, we probably won't have permission to
       do this. Not considered a fatal error anymore. */
    if (mlock((void *)g_command_table,
              MAX_NUM_SECRETS*sizeof(OST_cmdtable_elem_t))) {
      /* Uh oh. Warn the user. */
      Log_Message(LOG_NOTICE, "Could not lock password memory: %m.");
    }
#endif
    /* This can be overrriden, or cleared entirely, by the cfg file. */
    sprintf(g_pidfile_name, "/var/run/ostiaryd.pid");

    /* We only do this the first time. If we reinitialize from a SIGHUP,
       we want to read from the same file again. */
    memset(g_cfgfile_path, 0, MAX_PATHNAME_SIZE);

    /* Init IP addr... */
    memset(&g_local_ip, 0, sizeof(g_local_ip));
    g_local_ip.s_addr = INADDR_ANY; /* Can be overridden by cfg file. */

    g_port = g_exit_on_cache_full = g_ignore_urandom = g_skip_detach = 0;

    g_total_errors = g_max_total_errors = g_max_single_errors = 0;

    g_current_action = 0;

    /* May be overridden by config file... */
    g_connect_delay = DEFAULT_CONNECT_DELAY;
    g_max_bad_conns = DEFAULT_MAX_BAD_CONNS;
    g_comm_timeout = DEFAULT_COMM_TIMEOUT;
    memset(&cmdline_opts, 0, sizeof(cmdline_opts));

    Init_Ip_Cache();

    srandom(time(NULL)); /* May be overrriden by cmdline opt below. */

    /* Get the command-line options */
    if (Get_Cmdline_Options(argc, argv, &cmdline_opts)) {
      Log_Message(LOG_ERR, "Error parsing command-line options!\n");
      return -1;
    } else {
      Log_Message(LOG_INFO, "Command-line options processed.\n");
    }

    /* Set this before config file; cfg file can override if needed. */
    Set_Default_IDs();
  }

  /* Did the user set the config file on the command line? */
  if (!g_cfgfile_path[0]) {
    /* Guess not. Look for the usual suspects. */
    i=0;
    while(g_cfg_paths[i]) {
      memset(g_cfgfile_path, 0, MAX_PATHNAME_SIZE);
      memcpy(g_cfgfile_path, g_cfg_paths[i], strlen(g_cfg_paths[i]));
      strncat(g_cfgfile_path, DEFAULT_CFGFILE_NAME,
              MAX_PATHNAME_SIZE - (strlen(g_cfg_paths[i])+1));
      /* Parse config file, set options */
      if (0 == Parse_Config_File(g_cfgfile_path, g_param_table)) {
        Log_Message(LOG_NOTICE, "Config file '%s' valid.\n",
                    g_cfgfile_path);
        break;
      } else {
        i++;
      }
    }
    if (!g_cfg_paths[i]) {
      /* We went through all the candidates. */
      Log_Message(LOG_ERR, "Unable to find valid config file!\n");
      return -1;
    }
  } else {
    if (Parse_Config_File(g_cfgfile_path, g_param_table)) {
      Log_Message(LOG_ERR, "Error processing config file '%s'!\n",
                  g_cfgfile_path);
      return -1;
    }
  }

  /* Let the command-line opts override the config file... the first
     time, anyway. */
  if (first) {
    if (cmdline_opts.connect_delay) {
      g_connect_delay = cmdline_opts.connect_delay;
    }
    if (cmdline_opts.port) {
      g_port = cmdline_opts.port;
    }
    if (cmdline_opts.ignore_urandom) {
      g_ignore_urandom = cmdline_opts.ignore_urandom;
    }
    if (cmdline_opts.local_ip_set) {
      g_local_ip = cmdline_opts.local_ip;
    }
  }

  /*** Okay, if we made it this far we have apparently-valid config info. ***/

  /** Sanity-check the values. **/

  if (!g_connect_delay) {
    /* Can't have a zero delay. Too bad. */
    g_connect_delay = DEFAULT_CONNECT_DELAY;
    Log_Message(LOG_DEBUG,
                "Using default connect delay '%d'.\n", g_connect_delay);
  }

  /* Gotta have valid port. */
  if (!g_port) {
    Log_Message(LOG_ERR, "Listen port not set!\n");
    return -1;
  }

  /* Gotta have valid kill secret. */
  if (!g_kill_secret[0]) {
    Log_Message(LOG_ERR, "Kill password undefined!\n");
    return -1;
  }

  /* Gotta have at least one action. */
  if (!(g_command_table[0].secret[0])) {
    Log_Message(LOG_ERR, "No actions specified!\n");
    return -1;
  }

  /* If available, use /dev/urandom... */
  if (!g_ignore_urandom &&
      0 > (g_randfile = open("/dev/urandom", O_RDONLY))) {
    Log_Message(LOG_NOTICE, "/dev/urandom not available, using random().\n");
  }

  /* Set up the socket, bind it, etc. */
  if (-1 == (*listen_sock = socket(PF_INET, SOCK_STREAM, 0))) {
    Log_Message(LOG_ERR, "Could not allocate socket: %m!");
    return -1;
  }

  i=1; /* used as the 'reuse' parameter setsockopt */
  if (setsockopt(*listen_sock, SOL_SOCKET, SO_REUSEADDR,
                 (char *)&i, sizeof(i))) {
    /* Oh, well, this isn't too critical. It's just nice to
       be able to stop and restart the server quickly on the
       same port. */
    Log_Message(LOG_NOTICE, "Could not set socket reuse: %m.");
  }

  /* Set up the socket address. */
  memset(listen_addr, 0, sizeof(listen_addr));
  listen_addr->sin_family = AF_INET;
  listen_addr->sin_addr.s_addr = g_local_ip.s_addr;
  listen_addr->sin_port = htons(g_port);
  Log_Message(LOG_DEBUG, "ip:%s, port:%d.", inet_ntoa(g_local_ip), g_port);

  /* Bind, listen. */
  if (bind(*listen_sock, (struct sockaddr *)listen_addr,
           sizeof(*listen_addr))) {
    Log_Message(LOG_ERR, "Could not bind to socket: %m!");
    return -1;
  }
  /* Note that we only allow a backlog of one connection. */
  if (-1 == listen(*listen_sock, 1)) {
    Log_Message(LOG_ERR, "Failed listen() on socket: %m!");
    return -1;
  }

  /* Detach from parent process, etc. (Only do this once.) */
  if (first && Daemonize()) {
    Log_Message(LOG_ERR, "Problem detaching!\n");
    return -1;      
  }

  Create_PID_File(); /* Looks like we'll be sticking around for a
                        while. */
  /* Didn't return before now. All must be well. */

  Log_Message(LOG_NOTICE, "Initialization completed.\n");
  return 0;
}

/* Send 'buf_len' bytes of data, unless 'timeout' seconds have
   passed. */
int Send_With_Timeout(int send_sock, unsigned char *send_buf, size_t buf_len,
                      int timeout)
{
  int cur_data_pos=0, bytes_sent, sel_ret;
  time_t cur_time, start_time;
  struct timeval time_val;
  fd_set fdSet;

  time(&start_time);

  while (cur_data_pos < buf_len) {
    time(&cur_time);
    if (timeout < cur_time - start_time) {
      /* We didn't make it. */
      Log_Message(LOG_ERR,"Timeout sending data, sent %d bytes!\n",
                 cur_data_pos); 
      return -1;
    }
    /* How long we wait this round. */
    memset(&time_val, 0, sizeof(time_val));
    time_val.tv_sec = timeout - (cur_time - start_time);

    FD_ZERO(&fdSet);
    FD_SET(send_sock, &fdSet);
    if (-1 == (sel_ret = select((SELECT_TYPE_ARG1) send_sock+1,
                                NULL, SELECT_TYPE_ARG234 &fdSet,
                                NULL, SELECT_TYPE_ARG5 &time_val))) {
      Log_Message(LOG_ERR, "Calling select on socket: %m!");
      return -1;
    }

    if (sel_ret) {
      /* Okay, we're good. Let's send some data. */
      bytes_sent = send(send_sock, &(send_buf[cur_data_pos]),
                        buf_len - cur_data_pos, 0);
      if (-1 == bytes_sent) {
        Log_Message(LOG_ERR, "Failed send(): %m!");
        return -1;
      }
      if (0 == bytes_sent) {
        Log_Message(LOG_ERR,"Didn't send full amount of data!\n");
        return -1;        
      } else {
        if (bytes_sent < buf_len - cur_data_pos) {
          /* Might not have sent everything yet... but 16 bytes
             should fit in one packet, so it'd be pretty weird
             if we didn't... */
          Log_Message(LOG_WARNING, "Send() sent only %d bytes.\n", bytes_sent);
        }
        cur_data_pos += bytes_sent;
      }
    } else {
      Log_Message(LOG_ERR, "Select() timed out, giving up.\n");
      return -1;
    }
  }
  return 0;
}

/* Receive 'buf_len' bytes of data, unless 'timeout' seconds have
   passed. */
int Recv_With_Timeout(int recv_sock, unsigned char *read_buf, size_t buf_len,
                      int timeout)
{
  int cur_data_pos=0, bytes_read, sel_ret;
  time_t cur_time, start_time;
  struct timeval time_val;
  fd_set fdSet;

  time(&start_time);

  while (cur_data_pos < buf_len) {
    time(&cur_time);
    if (timeout < cur_time - start_time) {
      /* We didn't make it. */
      Log_Message(LOG_ERR, "Timeout receiving data, received %d bytes!\n",
                 cur_data_pos); 
      return -1;
    }
    /* How long we wait this round. */
    memset(&time_val, 0, sizeof(time_val));
    time_val.tv_sec = timeout - (cur_time - start_time);

    FD_ZERO(&fdSet);
    FD_SET(recv_sock, &fdSet);
    if (-1 == (sel_ret = select((SELECT_TYPE_ARG1) recv_sock+1,
                                SELECT_TYPE_ARG234 &fdSet,
                                NULL, NULL, SELECT_TYPE_ARG5 &time_val))) {
      Log_Message(LOG_ERR, "Calling select on socket: %m!");
      return -1;
    }

    if (sel_ret) {
      /* Okay, we're good. Let's read some data. */
      bytes_read = recv(recv_sock, &(read_buf[cur_data_pos]),
                        buf_len - cur_data_pos, 0);
      if (-1 == bytes_read) {
        Log_Message(LOG_ERR, "Failed recv(): %m!");
        return -1;
      }
      if (0 == bytes_read) {
        Log_Message(LOG_ERR, "Didn't receive full amount of data!\n");
        return -1;
      } else {
        if (bytes_read < buf_len - cur_data_pos) {
          /* Might not have read everything yet... but 16 bytes
             should fit in one packet, so it'd be pretty weird
             if we didn't... */
          Log_Message(LOG_WARNING, "Recv() only read %d bytes.\n", bytes_read);
        }
        cur_data_pos += bytes_read;
      }
    } else {
      Log_Message(LOG_ERR, "Select() timed out, giving up.\n");
      return -1;
    }
  }
  return 0;
}

/* Use /dev/urandom if available, else just use pseudo-random generator.
   The security doesn't really depend on the value of the seed hash
   being unpredictable anyway. There's no point in feeding more than
   HASH_BIN_SIZE random bytes, since that's the maximum amount of
   randomness we get out from the hash function.

   Since we limit connections to at most once per second, the most this
   could try to grab is 128 bits/sec. On an unattended server (no kb or
   mouse input) with little work to do (few interrupts/sec) this might
   exhaust the entropy pool. The truly paranoid can find a hardware
   RNG (e.g. i810 RNG, processed microphone input, gieger counter) to
   make sure there's always enough entropy for Ostiary and any other
   secure apps on the system (e.g. an SSL server...)

   Assumes ints are 32 bits, but even on 64-bit platforms this is
   currently true. */
void Make_Seed_Hash(unsigned char *sent_hash)
{
  time_t cur_time;
  char rand_seed[HASH_BIN_SIZE];

  if (0 < g_randfile) {
    if (-1 == read(g_randfile, rand_seed, HASH_BIN_SIZE)) {
      Log_Message(LOG_ERR, "Problem reading from /dev/urandom: %m!");
      /* Fall back to random() */
      *(int *)rand_seed = (int)random();
      *(int *)(&rand_seed[4]) = (int)random();
      *(int *)(&rand_seed[8]) = (int)random();
      *(int *)(&rand_seed[12]) = (int)random();
    }
  } else {
    /* /dev/urandom not available, just use random() */
    *(int *)rand_seed = (int)random();
    *(int *)(&rand_seed[4]) = (int)random();
    *(int *)(&rand_seed[8]) = (int)random();
    *(int *)(&rand_seed[12]) = (int)random();
  }

  /* Mix in the current time, just in case the RNG is broken and somehow
     ends up returning the same value over and over. */
  time(&cur_time);

  cur_time ^= g_my_pid; /* Just for grins, throw in current PID, too. Hard
                           for an attacker not on the box to guess. */

  /* An attacker might know the time, but HMAC makes it as hard as
     possible for them to figure out what random seed we used. */
  Do_Ostiary_Hash((unsigned char *)&cur_time, sizeof(cur_time),
               rand_seed, HASH_BIN_SIZE, sent_hash);
}

/* Function to make sure passwords are eliminated from memory before
   we exit. */
void Clear_Password_Memory()
{
  int i;

  for(i=0; i<MAX_NUM_SECRETS; i++) {
    forced_memset(g_command_table[i].secret, 0, MAX_SECRET_SIZE);
  }
}

/* Set a flag when we get SIGHUP. */
void Hup_Handler(int sig)
{
  g_sighup_flag = 1;
}

/* Here's where all the magic happens. */
int main(int argc, char *argv[])
{
  int i, listen_sock, clnt_sock, success;
  size_t struct_len;
  char hash_out_buf[HASH_TEXT_SIZE]; /* for debug output */
#if HAVE_SIGACTION
  struct sigaction sigact;
#endif
 
  struct sockaddr_in listen_addr, clnt_addr;
  unsigned char sent_hash[HASH_BIN_SIZE], received_hash[HASH_BIN_SIZE],
    local_hash[HASH_BIN_SIZE];

  /* Special, one-time initializations. */

  /* Do our best to ensure we can't leak passwords. */
  atexit(Clear_Password_Memory);

#if HAVE_SIGACTION
  /* Clear the sighup flag. */
  g_sighup_flag = 0;

  /* Malicious clients or bad networks can raise SIGPIPE; we'll catch
     it anyway in the return code. */
  memset(&sigact, 0, sizeof(sigact));
  sigact.sa_handler = SIG_IGN; /* Ignore this signal. */
  sigaction(SIGPIPE, &sigact, NULL);

  /* Handle SIGHUP (for restarting the daemon). */
  sigact.sa_handler = Hup_Handler;
  sigaction(SIGHUP, &sigact, NULL);

  /* So we process this signal in a timely manner, set things up
     so SIGHUP will interrupt a syscall. */
  siginterrupt(SIGHUP, 1);
#endif

  /* Init global vars, read configs, etc. */
  if (OST_Init(argc, argv, &listen_sock, &listen_addr, 1)) {
    printf("Problem in initialization, check log file!\n");
    return -1;
  }

  Log_Message(LOG_INFO, "Ostiary v" PACKAGE_VERSION " waiting for commands...");

  /* Okay, we're ready. Loop until killed. */
  while (1) {

    /* If we've gotten SIGHUP, re-initialize. */
    if (g_sighup_flag) {
      Log_Message(LOG_NOTICE, "Reinitializing on SIGHUP signal.\n");
      if (OST_Init(argc, argv, &listen_sock, &listen_addr, 0)) {
        Log_Message(LOG_ERR, "Reinitialization failed, exiting!\n");
        return -1;
      }
      g_sighup_flag = 0;
    }

    /* Yes, this slows startup. However, it's the simplest way to ensure
       that the delay always happens, without duplicating code all over
       the place. */
    sleep(g_connect_delay); /* sleep for user-specified seconds */

    /* Accept connections. */
    struct_len = sizeof(clnt_addr);
    if (-1 == (clnt_sock = accept(listen_sock,
                                  (struct sockaddr *)&clnt_addr,
                                  &struct_len))) {
      Log_Message(LOG_ERR, "Problem accepting connection: %m!");
      /* Note: if we got here because a syscall was interrupted,
         we shouldn't add whatever IP's in the clnt_addr struct
         to the IP cache, (a) it may not be valid, and (b) even
         if it's a valid address, it wasn't their fault. */
      if (EINTR != errno && sizeof(clnt_addr) == struct_len) {
        Add_Or_Update_IP(clnt_addr.sin_addr);
      }
      continue; /* Skip rest of loop. Can't communicate. */
    }

#if HAVE_LIBWRAP
    if (!hosts_ctl("ostiaryd", STRING_UNKNOWN, inet_ntoa(clnt_addr.sin_addr),
                   STRING_UNKNOWN)) {
      Log_Message(LOG_WARNING, "Refused ip '%s' due to TCP wrappers.",
                      inet_ntoa(clnt_addr.sin_addr));
      close(clnt_sock); /* Bye-bye! */
      continue; /* Skip rest of loop. This sucker's unwelcome. */
    }
#endif

    if (Check_Addr_Against_Cache(clnt_addr.sin_addr, 0)) {
      Log_Message(LOG_WARNING, "Refused locked client '%s'.\n",
                 inet_ntoa(clnt_addr.sin_addr));
      close(clnt_sock); /* Bye-bye! */
      continue; /* Skip rest of loop. This sucker's locked out. */
    }

    /* Construct the finest random hash available. */
    Make_Seed_Hash(sent_hash);

    /* For debugging. */
    Print_Hash(sent_hash, hash_out_buf, HASH_TEXT_SIZE);
    Log_Message(LOG_DEBUG, "Sending hash '%s' to %s.\n", hash_out_buf,
                inet_ntoa(clnt_addr.sin_addr));
    
    if (Send_With_Timeout(clnt_sock, sent_hash, HASH_BIN_SIZE,
                          g_comm_timeout)) {
      Log_Message(LOG_WARNING,
                  "Client '%s' did not accept data within %d seconds.\n",
                 inet_ntoa(clnt_addr.sin_addr),
                 g_comm_timeout);
      close(clnt_sock); /* Bye-bye! */
      /* This is a strike against this ip addr. */
      Add_Or_Update_IP(clnt_addr.sin_addr);
      continue; /* Skip rest of loop. */
    }

    /* Receive reply. */
    if (Recv_With_Timeout(clnt_sock, received_hash, HASH_BIN_SIZE,
                          g_comm_timeout)) {
      Log_Message(LOG_WARNING,
                  "Client '%s' did not send full data within %d seconds.\n",
                 inet_ntoa(clnt_addr.sin_addr),
                 g_comm_timeout);
      close(clnt_sock); /* Bye-bye! */
      /* This counts against this ip addr. */
      Add_Or_Update_IP(clnt_addr.sin_addr);
      continue; /* Skip rest of loop. */
    }
    close(clnt_sock); /* We're all done receiving. */

    Print_Hash(received_hash, hash_out_buf, HASH_TEXT_SIZE);
    Log_Message(LOG_DEBUG, "Received hash '%s' from '%s'.\n", hash_out_buf,
                inet_ntoa(clnt_addr.sin_addr));

    /* Check for kill command... */
    Do_Ostiary_Hash((unsigned char *)sent_hash, HASH_BIN_SIZE, g_kill_secret,
            strlen(g_kill_secret), local_hash);

    Print_Hash(local_hash, hash_out_buf, HASH_TEXT_SIZE);
    Log_Message(LOG_DEBUG, "Kill hash is '%s'\n", hash_out_buf);

    if (!memcmp(received_hash, local_hash, HASH_BIN_SIZE)) {
      Log_Message(LOG_CRIT, "Received valid kill signal from '%s', exiting.\n",
                 inet_ntoa(clnt_addr.sin_addr));
      break; /* break out of forever loop */
    }

    /* Now, compare to the local secrets... */
    for(success=0, i=0;
        i<MAX_NUM_SECRETS && g_command_table[i].command[0]; i++) {

      Do_Ostiary_Hash((unsigned char *)sent_hash, HASH_BIN_SIZE,
              g_command_table[i].secret, strlen(g_command_table[i].secret),
              local_hash);

      Print_Hash(local_hash, hash_out_buf, HASH_TEXT_SIZE);
      Log_Message(LOG_DEBUG, "Command %d hash is '%s'.\n", i, hash_out_buf);
      
      /* If they match... */
      if (!memcmp(received_hash, local_hash, HASH_BIN_SIZE)) {
        /* Set to break out of outer loop. */
        success = 1;

        /* Reset bad connection count if needed. */
        Check_Addr_Against_Cache(clnt_addr.sin_addr, 1);

        Log_Message(LOG_NOTICE, "Valid hash from ip '%s', executing '%s'.\n",
                 inet_ntoa(clnt_addr.sin_addr),
                   g_command_table[i].command);
        /* Perform designated action */
        if (Run_Command(g_command_table[i].command,
                        clnt_addr.sin_addr,
                        g_command_table[i].new_uid,
                        g_command_table[i].new_gid)) {
          Log_Message(LOG_ERR, "Error running command '%s'!\n",
                     g_command_table[i].command);
        }
        /* break outta this loop */
        break;
      }
    } /* end loop through secrets */

    if (!success) {
      /* We didn't find a match. Log error, update cache */
      Log_Message(LOG_ERR, "Bogus hash received from ip '%s'!\n",
                 inet_ntoa(clnt_addr.sin_addr));
      Add_Or_Update_IP(clnt_addr.sin_addr);
    }
  } /* end forever loop */

  /* This should be redundant due to the atexit() call above, but
     as long as we're being paranoid... */
  Clear_Password_Memory();

  Remove_PID_File();

  Close_Log_File(); /* G'night. */

  return EXIT_SUCCESS;
}
