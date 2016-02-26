/* ost_debug.c - Debug output functions.
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

#include "ost_debug.h"

/* Open log file. */
void Open_Log_File(const char *ident)
{
  openlog(ident, LOG_CONS, LOG_AUTH);
}

/* Close log file. */
void Close_Log_File()
{
  closelog();
}

/* Set the log level. Not all systems define LOG_UPTO()... */
void Set_Log_Level(int min_level)
{
  int log_mask=0;

  /* Set the appropriate masks. */
  switch(min_level) {
  case LOG_DEBUG:
    log_mask |= LOG_MASK(LOG_DEBUG);
  case LOG_INFO:
    log_mask |= LOG_MASK(LOG_INFO);
  case LOG_NOTICE:
    log_mask |= LOG_MASK(LOG_NOTICE);
  case LOG_WARNING:
    log_mask |= LOG_MASK(LOG_WARNING);
  case LOG_ERR:
    log_mask |= LOG_MASK(LOG_ERR);
  case LOG_CRIT:
    log_mask |= LOG_MASK(LOG_CRIT);
  case LOG_ALERT:
    log_mask |= LOG_MASK(LOG_ALERT);
  case LOG_EMERG:
    log_mask |= LOG_MASK(LOG_EMERG);
  }

  setlogmask(log_mask);
}
