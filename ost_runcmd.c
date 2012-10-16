/* ost_runcmd.c - Implementation of external commands, including uid/gid
   handling.
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
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ost.h"
#include "ost_globals.h"
#include "ost_runcmd.h"
#include "ost_debug.h"

/* Sets the uid and/or gid for the new command. */
static int Set_IDs(uid_t new_uid, gid_t new_gid)
{
  /* Note: set gid BEFORE setting uid, or else we might lose the
     ability to do so! */
  if (setgid(new_gid)) {
    Log_Message(LOG_ERR, "Could not set gid to '%d', err=%d!", new_gid, errno);
    return -1;
  }
  if (setuid(new_uid)) {
    Log_Message(LOG_ERR,"Could not set uid to '%d', err=%d!",
                new_uid, errno);
    return -1;
  }
  /* All must be well. */
  return 0;
}

/* Fire off a command. This is slightly tricky. We don't want to
   have to deal with SIGCHILD or spawn a thread to call 'wait()'
   or anything like that, but we obviously don't want zombies
   either. So we do something slightly funky during the fork.

   We spawn off a child, and *that* child actually spawns off
   the command. The first child exits, so the second child (the
   command) becomes a child of 'init'. The main process collects
   the first child's exit status, and everyone's happy. */
int Run_Command(char *command, struct in_addr remote_ip,
                uid_t new_uid, gid_t new_gid)
{
  pid_t pid;
  int status, i;
  char *argv[3];
  char rem_ip_str[MAX_SIZEOF_IP];

  if (NULL == command) {
    return -1;
  }

  snprintf(rem_ip_str, MAX_SIZEOF_IP, "%s", inet_ntoa(remote_ip));
  Log_Message(LOG_DEBUG,"IP address '%x' decodes as '%s'.\n",
               (int)remote_ip.s_addr, rem_ip_str);

  /* Construct arg list */
  argv[0] = command;
  argv[1] = rem_ip_str;
  argv[2] = NULL;

  Log_Message(LOG_INFO,"Running command '%s %s'.\n", argv[0], argv[1]);

  if (0 > (pid = fork())) {
    /* Bad news! */
    Log_Message(LOG_ERR, "Fork failed for command '%s %s': %m!",
                argv[0], argv[1]);
    return -1;    
  }

  if (!pid) {
    /* We're the first child. */
    Clear_Password_Memory(); /* This process doesn't need this data, and we
                                don't want to leak it. */

    /* Set permissions if necessary. */
    if (Set_IDs(new_uid, new_gid)) {
      /* Problem setting perms, bail. */
      exit(EXIT_FAILURE);
    }

    /* We might not have perms now to write to the log, but oh well. */
    Log_Message(LOG_INFO,"Running '%s' as uid=%d, gid=%d.\n",
               command, getuid(), getgid());

    /* Get ready to fire off the actual command. */
    if (0 > (pid = fork())) {
      /* Bad news! Try to record the failure. */
      Log_Message(LOG_ERR, "Second fork failed for command '%s %s': %m!",
                argv[0], argv[1]);
      exit(EXIT_FAILURE);
    }

    if (!pid) {
      /* We're in the second child */

      /* First, don't give the child a copy of our open file descriptors. */

      for (i=getdtablesize();i>=2;--i) close(i); /* close all descriptors,
                                              except stdin, stdout, stderr */

      /* Let's exec() the command. */
      execv(command, argv);

      /* We should never get to this point. */
      Log_Message(LOG_ERR, "Exec failed for command '%s %s': %m",
                  argv[0], argv[1]);
      exit(EXIT_FAILURE);
    }

    /* If we made it here, we're in the first child. Time to go
       bye-bye. */
    exit(EXIT_SUCCESS);
  }

  /* If we're here, we're in the main program. Let's collect
     the exit status of the first child. */
  waitpid(pid, &status, 0);

  if (!WIFEXITED(status) || EXIT_FAILURE ==  WEXITSTATUS(status)) {
    return -1;
  }

  /* It's all good. */
  return 0;
}
