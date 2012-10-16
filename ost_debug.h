/* ost_debug.h - Declaration of debug output functions.
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
#ifndef _OST_DEBUG_H_
#define _OST_DEBUG_H_

#include <syslog.h>

void Open_Log_File(const char *ident);
void Close_Log_File();
void Set_Log_Level(int min_level);

#define Log_Message syslog

#endif /* _OST_DEBUG_H_ */
