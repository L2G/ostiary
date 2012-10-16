/* ost_ipcache.h - Declaration of ip address recording functions.
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
#ifndef _OST_IPCACHE_H_
#define _OST_IPCACHE_H_

void Init_Ip_Cache();
int Check_Addr_Against_Cache(struct in_addr clnt_addr, int clear);
void Add_Or_Update_IP(struct in_addr clnt_addr);

#endif /* _OST_IPCACHE_H_ */
