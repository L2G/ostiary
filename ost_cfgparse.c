/* ost_cfgparse.c - Implementation of configuration file parsing functions.
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
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

#include "ost.h"
#include "ost_debug.h"
#include "ost_globals.h"
#include "ost_cfgparse.h"

/* NULL-terminate at first '#', to handle comments at end of line. 
   09-09-15: Ignore '#' in quoted strings. */
void Kill_Comments(char *line_buf) {
  int i, in_qstring=0;

  for (i=0; i<LINEBUF_SIZE; i++) {
    if (!in_qstring && '"' == line_buf[i]) {
      in_qstring=1;
      continue;
    }
    if (!in_qstring && '#' == line_buf[i]) {
      line_buf[i] = 0;
      break;
    }
   if (in_qstring && '"' == line_buf[i]) {
     /* Make sure quote isn't escaped. (Note, i-1 is guaranteed to be >=0,
        since in_qstring can't be true for i=0.) */
     if ('\\' != line_buf[i-1]) {
       /* Okay, wasn't escaped, out of quoted string. */
       in_qstring=0;
       continue;
     }
   }
  }
}

/* Skip past leading whitespace. */
int Skip_Whitespace(char *line_buf) {
  int i;

  for (i=0; i<LINEBUF_SIZE; i++) {
    if (!isspace(line_buf[i])) {
      return(i);
    }
  }
  /* Hey! Nothing but whitespace? */
  return 0;
}

/* Extract first quoted substring from within a string,
   and store in 'dest', check size along way. Returns
   position after substring, or NULL on error. An empty
   string is not an error. */
static char *Get_Quoted_Substring(char *dest, char *src, size_t dest_size)
{
  int done=0;
  char *open_quote_pos, *close_quote_pos;

  /* Clear the destination buffer. */
  memset(dest, 0, dest_size);

  Log_Message(LOG_DEBUG, "String is now '%s'\n", src);

  /* Will skip whitespace */
  if (NULL == (open_quote_pos = strchr(src, '"'))) {
    Log_Message(LOG_ERR, "Did not find opening '\"'!\n");
    return NULL;
  }

  /* Allow " in string, so long as it's escaped with '\'. */
  while (!done) {
    if (NULL == (close_quote_pos = strchr(open_quote_pos+1, '"'))) {
      Log_Message(LOG_ERR, "Did not find closing '\"'!\n");
      return NULL;
    }
    if ('\\' != *(close_quote_pos-1)) {
      /* found a non-escaped quote */
      done = 1;
    }
  }

  if (close_quote_pos - open_quote_pos - 1 < dest_size) {
    /* Copy the substring. */
    Log_Message(LOG_INFO, "Value is '%s'.\n",
              strncpy(dest, open_quote_pos+1,
                      close_quote_pos - open_quote_pos - 1));
  } else {
      Log_Message(LOG_ERR,"String too large!\n");
      return NULL;
  }

  /* All is well. */
  return close_quote_pos+1;
}

/* Process a toggle parameter. */
static int Process_Cfg_Toggle(char *line_buf, OST_cfgparam_elem param_elem)
{
  assert(param_elem.param_ptr != NULL);
  /* Set to true. */
  *(short *)(param_elem.param_ptr) = 1;
  return 0;
}

/* Process an ip address. */
static int Process_Cfg_IP_Addr(char *line_buf, OST_cfgparam_elem param_elem)
{
  char *cur_str_pos;

  assert(param_elem.param_ptr != NULL);

  /* Find the '=' */
  if (NULL == (cur_str_pos = strchr(line_buf, '='))) {
    Log_Message(LOG_ERR, "Did not find  '='!\n");
    return -1;
  }
  /* Skip the '=' itself. */
  cur_str_pos++;

  if (!inet_aton(cur_str_pos,
                 (struct in_addr *)(param_elem.param_ptr))) {
    Log_Message(LOG_ERR,"Cannot process ip address '%s'!\n",
              cur_str_pos);
    return -1;
  }
  /* Debug output... */
  Log_Message(LOG_INFO, "'%s' address is '%s'\n", param_elem.param_name,
            inet_ntoa(*(struct in_addr *)(param_elem.param_ptr)));
  return 0;
}

/* Process an id parameter. (Note: I assume that uids and gid are
   the same size and format.) */
static int Process_Cfg_ID(char *line_buf, OST_cfgparam_elem param_elem)
{
  char *cur_str_pos;

  assert(param_elem.param_ptr != NULL);

  /* Find the '=' */
  if (NULL == (cur_str_pos = strchr(line_buf, '='))) {
    Log_Message(LOG_ERR, "Did not find  '='!\n");
    return -1;
  }
  /* Skip the '=' itself. */
  cur_str_pos++;

  /* Note: atoi() skips whitespace. */
  *(uid_t *)(param_elem.param_ptr) = atoi(cur_str_pos);
  /* Debug output... */
  Log_Message(LOG_INFO,"'%s' value is '%d'\n", param_elem.param_name,
            *(uid_t *)(param_elem.param_ptr));
  return 0;
}

/* Process an integer parameter. */
static int Process_Cfg_Int(char *line_buf, OST_cfgparam_elem param_elem)
{
  char *cur_str_pos;

  assert(param_elem.param_ptr != NULL);

  /* Find the '=' */
  if (NULL == (cur_str_pos = strchr(line_buf, '='))) {
    Log_Message(LOG_ERR, "Did not find  '='!\n");
    return -1;
  }
  /* Skip the '=' itself. */
  cur_str_pos++;

  /* Note: atoi() skips whitespace. */
  switch (param_elem.elemtype) {
  case OST_INT:
    *(int *)(param_elem.param_ptr) = atoi(cur_str_pos);
    /* Debug output... */
    Log_Message(LOG_INFO, "'%s' value is '%d'\n", param_elem.param_name,
               *(int *)(param_elem.param_ptr));
    break;
  case OST_SHORT:
    *(short *)(param_elem.param_ptr) = atoi(cur_str_pos);
    /* Debug output... */
    Log_Message(LOG_INFO, "'%s' value is '%d'\n", param_elem.param_name,
               *(short *)(param_elem.param_ptr));
    break;
  default:
    Log_Message(LOG_ERR, "Error, bad value in param table, %d!\n",
              param_elem.elemtype);
    return -1;
  }
  return 0;
}

/* Process a log level. (Some systems don't provide LOG_UPTO(), so we
   just do it ourselves.) */
static int Process_Cfg_Loglevel(char *line_buf, OST_cfgparam_elem param_elem)
{
  char *cur_str_pos;

  /* Find the '=' */
  if (NULL == (cur_str_pos = strchr(line_buf, '='))) {
    Log_Message(LOG_ERR, "Did not find  '='!\n");
    return -1;
  }
  /* Skip the '=' itself. */
  cur_str_pos++;

  if (!strncmp(cur_str_pos, "LOG_EMERG", strlen("LOG_EMERG"))) {
    Set_Log_Level(LOG_EMERG);
  } else if (!strncmp(cur_str_pos, "LOG_ALERT", strlen("LOG_ALERT"))) {
    Set_Log_Level(LOG_DEBUG);
  } else if (!strncmp(cur_str_pos, "LOG_CRIT", strlen("LOG_CRIT"))) {
    Set_Log_Level(LOG_DEBUG);
  } else if (!strncmp(cur_str_pos, "LOG_ERR", strlen("LOG_ERR"))) {
    Set_Log_Level(LOG_ERR);
  } else if (!strncmp(cur_str_pos, "LOG_WARNING", strlen("LOG_WARNING"))) {
    Set_Log_Level(LOG_WARNING);
  } else if (!strncmp(cur_str_pos, "LOG_NOTICE", strlen("LOG_NOTICE"))) {
    Set_Log_Level(LOG_NOTICE);
  } else if (!strncmp(cur_str_pos, "LOG_INFO", strlen("LOG_INFO"))) {
    Set_Log_Level(LOG_INFO);
  } else if (!strncmp(cur_str_pos, "LOG_DEBUG", strlen("LOG_DEBUG"))) {
    Set_Log_Level(LOG_DEBUG);
  } else {
    Log_Message(LOG_ERR, "Unknown log level '%s'!\n",
                cur_str_pos);
    return -1;
  }
  /* It must be all good. */
  return 0;
}

/* Process a string parameter. */
static int Process_Cfg_String(char *line_buf, OST_cfgparam_elem param_elem)
{
  char *cur_str_pos;

  assert(param_elem.param_ptr != NULL);

  /* Find the '=' */
  if (NULL == (cur_str_pos = strchr(line_buf, '='))) {
    Log_Message(LOG_ERR, "Did not find  '='!\n");
    return -1;
  }

  if (NULL == Get_Quoted_Substring(
                          (char *)param_elem.param_ptr,
                          cur_str_pos+1,
                          param_elem.data_size)) {
    Log_Message(LOG_ERR, "Did not find value!\n");
    return -1;
  }

  /* Debug output... */
  Log_Message(LOG_INFO, "'%s' value is '%s'\n", param_elem.param_name,
            (char *)param_elem.param_ptr);
  return 0;
}

#define MAX_ID_SIZE 12 /* Enough for a 32-bit number */

/* Process an action parameter. */
static int Process_Cfg_Action(char *line_buf, OST_cfgparam_elem *param_elem)
{
  char *cur_str_pos;
  int current_action;
  OST_cmdtable_elem_t *cmd_table =
    ((OST_cmdtable_elem_t *)param_elem->param_ptr);
  char id_buf[MAX_ID_SIZE];

  if (param_elem->data_size) {
    current_action = 0; /* It's a lockout action. */
    Log_Message(LOG_DEBUG, "Special action.\n");
  } else {
    current_action = g_current_action; /* It's a regular action. */
    Log_Message(LOG_DEBUG, "Creating action #%d.\n", current_action);
  }

  if (current_action >= MAX_NUM_SECRETS) {
    Log_Message(LOG_ERR, "Maximum number of commands (%d) exceeded!\n",
                MAX_NUM_SECRETS);
    return -1;
  }

  assert(param_elem->param_ptr != NULL);

  if (NULL == (cur_str_pos = strchr(line_buf, '='))) {
    Log_Message(LOG_ERR, "Did not find  '=' in '%s'!\n",
                param_elem->param_name);
    return -1;
  }

  /* Get the secret. */
  if (NULL == (cur_str_pos = Get_Quoted_Substring(
                    cmd_table[current_action].secret,
                    cur_str_pos+1,
                    MAX_SECRET_SIZE))) {
    Log_Message(LOG_ERR, "Did not find secret!\n");
    return -1;
  }

  if (NULL == (cur_str_pos = strchr(&line_buf[strlen(param_elem->param_name)],
                                    ','))) {
    Log_Message(LOG_ERR, "Separator ',' not found!\n");
    return -1;
  }

  /* Get the command value. */
  if (NULL == (cur_str_pos = Get_Quoted_Substring(
                    cmd_table[current_action].command,
                    cur_str_pos+1,
                    MAX_SECRET_SIZE))) {
    Log_Message(LOG_ERR, "Did not find command!\n");
    return -1;
  }

  /* Set the defaults, might be overidden below. */
  cmd_table[current_action].new_uid = g_default_uid;
  cmd_table[current_action].new_gid = g_default_gid;

  if (NULL == (cur_str_pos = strchr(cur_str_pos, ','))) {
    Log_Message(LOG_INFO, "No uid found.\n");
  } else {
    /* Is the user asking for something impossible? */
    if (getuid()) {
      Log_Message(LOG_ERR, "Must run as root to set uids!\n");
      return -1;
    }
    /* Okay, get the uid. */
    if (NULL == (cur_str_pos =
             Get_Quoted_Substring(id_buf, cur_str_pos+1, MAX_ID_SIZE))) {
      /* Gah, didn't find the uid! */
      Log_Message(LOG_ERR, "Error processing uid!\n");
      return -1;
    } else {
      cmd_table[current_action].new_uid =
        atoi(id_buf);
      Log_Message(LOG_INFO, "UID will be set to '%d'.\n",
           cmd_table[current_action].new_uid);
    }

    if (NULL == (cur_str_pos = strchr(cur_str_pos, ','))) {
      Log_Message(LOG_INFO, "No gid found.\n");
    } else {
      /* All right, grab that too. */
      if (NULL == (cur_str_pos =
               Get_Quoted_Substring(id_buf, cur_str_pos+1, MAX_ID_SIZE))) {
        /* Gah, didn't find the gid! */
        Log_Message(LOG_ERR, "Error processing gid!\n");
        return -1;
      } else {
        cmd_table[current_action].new_gid =
          atoi(id_buf);
        Log_Message(LOG_INFO, "GID will be set to '%d'.\n",
           cmd_table[current_action].new_gid);
      }
    }
  }

  /* Got this far, all must be well, right? */
  /* Debug output... */
  Log_Message(LOG_NOTICE, "Accepted command '%s'.\n",
          cmd_table[current_action].command);
  if (!param_elem->data_size) {
    g_current_action++; /* Keep track of how many we've done. */
  }
  return 0;
}

/* Parse the config file and set values. Don't override
   anything already set by a command-line option. */
int Parse_Config_File(char *cfg_file_name, OST_cfgparam_elem param_table[])
{
  int i, line_start, done=0;
  FILE *cfgFile;
  char line_buf[LINEBUF_SIZE];

  /* I'd initialize this in the declaration, but the Solaris
     compiler doesn't like empty initializers. */
  memset(line_buf, 0, LINEBUF_SIZE);

  /* Open file. */
  if (NULL == (cfgFile = fopen(cfg_file_name, "r"))) {
    Log_Message(LOG_ERR, "Couldn't open config file '%s': %m!\n",
                cfg_file_name);
    return -1;
  }

  /* For each line... */
  while (fgets(line_buf, LINEBUF_SIZE, cfgFile)) {
    Kill_Comments(line_buf);
    line_start = Skip_Whitespace(line_buf);
    if (strlen(line_buf) > line_start) {
      /* Something besides whitespace - should be a param. Let's parse it. */
      Log_Message(LOG_DEBUG, "Processing line '%s'.\n", line_buf);
      for (i=0, done=0; param_table[i].param_name && !done; i++) {
        if (!strncmp(line_buf, param_table[i].param_name,
                     strlen(param_table[i].param_name))) {
          /* Cool, we got a match. */
          switch(param_table[i].elemtype) {
          case OST_TOGGLE:
            /* Process as a toggle. */
            if (Process_Cfg_Toggle(&line_buf[line_start], param_table[i])) {
              goto bail;
            } else {
              done=1;
            }
            break;
          case OST_SHORT:
          case OST_INT:
            /* Process as an int. */
            if (Process_Cfg_Int(&line_buf[line_start], param_table[i])) {
              goto bail;
            } else {
              done=1;
            }
            break;
          case OST_LOGLEVEL:
            /* Process as log level. */
            if (Process_Cfg_Loglevel(&line_buf[line_start], param_table[i])) {
              goto bail;
            } else {
              done=1;
            }
            break;
          case OST_IP_ADDR:
            /* Process as an ip address. */
            if (Process_Cfg_IP_Addr(&line_buf[line_start], param_table[i])) {
              goto bail;
            } else {
              done=1;
            }
            break;
          case OST_ID:
            /* Process as an id (uid/gid). */
            if (Process_Cfg_ID(&line_buf[line_start], param_table[i])) {
              goto bail;
            } else {
              done=1;
            }
            break;
          case OST_STRING:
            /* Process as a string. */
            if (Process_Cfg_String(&line_buf[line_start], param_table[i])) {
              goto bail;
            } else {
              done=1;
            }
            done=1;
            break;
          case OST_ACTION:
            /* Process as an action. */
            if (Process_Cfg_Action(&line_buf[line_start], &param_table[i])) {
              goto bail;
            } else {
              done=1;
            }
            break;
          default:
            /* Should never happen! */
            Log_Message(LOG_ERR, "Internal error, bad table data!\n");
            return -1;
            break;
          }
          break; /* Break out of for loop, get next line */
        }
      }
      if (!done) {
      bail:
        Log_Message(LOG_ERR, "Error processing '%s'!\n", line_buf);
        return -1;
      }
    }
  }

  /* If we got this far, all is well. */
  Log_Message(LOG_INFO, "Config file '%s' processed.\n", cfg_file_name);
  return 0;
}
