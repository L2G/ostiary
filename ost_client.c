/* ost_client.c - Implementation of OST client.
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

#ifdef WIN32

/* Why do Windows sockets have to be gratuitously different from
   POSIX sockets? I mean, they stole the BSD TCP stack originally,
   was it so hard to keep the same interface? */

#include <winsock2.h>
#include "win_getopt.h"
#include "win_config.h"
#else
/* POSIX */
#include <time.h> /* time() */
#include <unistd.h>
#include <netdb.h>  /* gethostbyname() */
#include <sys/types.h>
#include <sys/socket.h> /* connect(), etc. */

#include <arpa/inet.h> /* inet_aton(), etc. */
#include "config.h"
#endif /* !WIN32 */

#include <stdio.h>
#include <string.h> /* strchr(), etc. */
#include <stdlib.h>
#include <ctype.h>

#include "ost.h"
#include "ost_hash.h"
#include "ost_getpass.h"
#include "ost_forced_memset.h"

int g_pass_fd;
unsigned short g_host_port;
unsigned short g_use_fd;
struct in_addr g_host_ip;
char g_cmd_secret[MAX_SECRET_SIZE];

#if WIN32
  char *optarg;
#else
/* Use regular Unix getopt. */
extern char *optarg;
extern int optind, opterr, optopt;
#endif

/* -a address, -p port, -v hash version*/
int Get_Cmdline_Options(int argc, char *argv[])
{
  char *cur_str_pos;
  struct hostent *hent;
  /* Use getopt(), set up any non-default values. */
  int c, error=0;
  int a_found = 0, p_found = 0, f_found = 0;

  /* Initialize cfg file name. */
#if WIN32
  while ((c = GetOption(argc, argv, "a:p:f:", &optarg))) {
#else
  while (EOF != (c = getopt(argc, argv, "a:p:f:"))) {
#endif
    switch (c) {
    case 'a':
      if (a_found) {
        /* Hey! We already did this option! */ 
        error = 1;
      } else {
        /* Okay, we've got an address. */
        a_found = 1;
        if ((cur_str_pos = strchr(optarg, ':'))) {
          p_found = 1;
          g_host_port = atoi(cur_str_pos+1);
          *cur_str_pos = 0; /* Terminate before port. */
        }
        if (NULL == (hent = gethostbyname(optarg))) {
         /* Not a name. */
#if WIN32
          if (g_host_ip.s_addr = inet_addr(optarg)) {
#else
          if (!inet_aton(optarg, &g_host_ip)) {
#endif
            /* Not a dotted quad either? */
            printf("Error parsing address: %s\n", optarg);
            error = 1;
          }
        } else {
          g_host_ip.s_addr = *(int *)(hent->h_addr_list[0]);
        }
      }
      break;
    case 'p': 
      if (p_found) {
        /* Hey! We already did this option! */
        error = 1;
      } else {
        g_host_port = atoi(optarg);
        p_found = 1;
      }
      break;
    case 'f': 
      if (f_found) {
        /* Hey! We already did this option! */
        error = 1;
      } else {
        g_use_fd = 1;
#ifndef WIN32
        g_pass_fd = atoi(optarg);
#endif
        f_found = 1;
      }
      break;
    default:
      error = 1; /* something's wrong. */
      break;
    }
    if (error) {
      /* Some kind of command line error. */
#if WIN32
      printf("osctlient v" PACKAGE_VERSION " usage: %s -a address [-p port] [-f]\n"
#else
      printf("osctlient v" PACKAGE_VERSION " usage: %s -a address [-p port] [-f fd]\n"
#endif
             "\t-a\taddress to contact - two formats:\n"
             "\t\t\taddress\n"
             "\t\t\taddress:port\n"
             "\t-p\tport (only needed if unspecified in -a)\n"
#if WIN32
             "\t-f\tread passphrase from standard input\n",
#else
             "\t-f\tread passphrase from indicated file descriptor\n",
#endif
             argv[0]);
      return -1;
    }
  }
  return 0; /* All's well that ends well */
}

int OST_Client_Init(int argc, char *argv[])
{
#if WIN32
	WSADATA ws_data;

	/* Try to get windows sockets going. */
	if (WSAStartup(MAKEWORD( 1, 1 ), &ws_data)) {
		return -1;
	}
#endif
  /* Clear all the vars. */
  memset(g_cmd_secret, 0, MAX_SECRET_SIZE);

  g_host_port = 0;

  /* Get the command-line options */
  if (Get_Cmdline_Options(argc, argv)) {
    fprintf(stderr, "Error parsing command-line options!\n");
    return -1;
  }

  /* Sanity-check the values. */

  /* Gotta have valid host address. */
  if (!g_host_ip.s_addr) {
    fprintf(stderr, "Host address not set!\n");
    return -1;
  }

  /* Gotta have valid port. */
  if (!g_host_port) {
    fprintf(stderr, "Host port not set!\n");
    return -1;
  }

  /* Didn't return before now. All must be well. */
  return 0;
}

int main(int argc, char *argv[])
{
  int send_sock, bytes_received;
  struct sockaddr_in host_addr;
  unsigned char send_hash[HASH_BIN_SIZE], recv_hash[HASH_BIN_SIZE];
  char hash_out_buf[HASH_TEXT_SIZE]; /* for debug output */

  /* Init global vars, read configs, etc. */
  if (OST_Client_Init(argc, argv)) {
    fprintf(stderr, "Problem in initialization, aborting!\n");
    return -1;
  }

  /* Get a socket. */
  if (-1 == (send_sock = socket(PF_INET, SOCK_STREAM, 0))) {
    perror("Could not allocate socket");
    return -1;
  }

  /* Set up the socket address. */
  memset(&host_addr, 0, sizeof(host_addr));
  host_addr.sin_family = AF_INET;
  host_addr.sin_addr.s_addr = g_host_ip.s_addr;
  host_addr.sin_port = htons(g_host_port);

  /* Get the secret. */
  if (g_use_fd) {
#if WIN32
    /* File descriptors aren't a Windows thing. So just read from
       stdin. */
    fscanf(stdin, "%s", g_cmd_secret);
#else
    if (!read(g_pass_fd, g_cmd_secret, MAX_SECRET_SIZE)) {
      fprintf(stderr, "Error reading passphrase from fd '%d': ", g_pass_fd);
      perror("");
      return -1;
    }
#endif
    bytes_received = strlen(g_cmd_secret);
    for (bytes_received = strlen(g_cmd_secret)-1;
          bytes_received > 0 && isspace(g_cmd_secret[bytes_received]);
           bytes_received--) {
      g_cmd_secret[bytes_received] = 0;
    }
    printf("pass: '%s'\n", g_cmd_secret);
  } else {
    Get_Password("Enter command secret: ", g_cmd_secret, MAX_SECRET_SIZE);
  }

  /* Connect. */
  if (connect(send_sock, (struct sockaddr *)&host_addr, sizeof(host_addr))) {
    fprintf(stderr, "Error connecting to '%s:%d': ",
            inet_ntoa(host_addr.sin_addr), g_host_port);
    perror("");
    return -1;
  }

  memset(recv_hash, 0, HASH_BIN_SIZE);

  /* Read the hash seed. */
  if (HASH_BIN_SIZE >
      (bytes_received = recv(send_sock, recv_hash, HASH_BIN_SIZE, 0))) {
    /* Some kind of problem. */
    if (bytes_received < 0) {
      /* Actual error. */
      perror("Failed to recv hash");
    } else {
      /* Not enough data. */
      fprintf(stderr, "Only got %d bytes of hash (locked out?).\n",
              bytes_received);
    }
    return -1;
  } else {
    Print_Hash(recv_hash, hash_out_buf, HASH_TEXT_SIZE);
    printf("Got hash: '%s'.\n", hash_out_buf);
  }

  /*Generate the hash to send. */
  Do_Ostiary_Hash((unsigned char *)recv_hash, HASH_BIN_SIZE,
               g_cmd_secret, strlen(g_cmd_secret), send_hash);

  /* Clear out secret, so there's minimal chance any other process
     can read it. */
  forced_memset(g_cmd_secret, 0, MAX_SECRET_SIZE);

  Print_Hash(send_hash, hash_out_buf, HASH_TEXT_SIZE);

  printf("Hash is: '%s'.\n", hash_out_buf);

  /* Send the hash. */
  if (0 > send(send_sock, send_hash, HASH_BIN_SIZE, 0)) {
    perror("Failed to send hash");
  }

#if WIN32
  closesocket(send_sock);
#else
  close(send_sock);
#endif

  /* All done. */
  printf("Hash sent.\n");

  return EXIT_SUCCESS;
}
