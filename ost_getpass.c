/* ost_getpass.c - Implementation of password-reading function.
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
#include <windows.h>
#include <stdio.h>
#else
#include <stdio.h>
#include <signal.h> /* sigprocmask(), etc. */
#include <termios.h> /* tcgetattr(), etc. */
#endif

/* After Stevens, but takes a pointer to a buffer and its size. */
int Get_Password(char *prompt, char *pass_buf, size_t buf_len)
{
#ifdef WIN32
  HANDLE in_hand;
  DWORD cons_mode;
  int count;

  printf("%s", prompt);
  in_hand = GetStdHandle(STD_INPUT_HANDLE);
  if (!in_hand) {
    return -1;
  }
  GetConsoleMode(in_hand, &cons_mode);
  SetConsoleMode(in_hand, ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
  ReadFile(in_hand, pass_buf, buf_len, &count, NULL);
  SetConsoleMode(in_hand, cons_mode);
  if (count) {
	pass_buf[count-2] = 0; /* Remove CR/LF */
  } else {
	  return -1;
  }
  printf("\n");
  return 0;
#else /* must be POSIX */
  char *ptr;
  sigset_t sig, sigsave;
  struct termios term, termsave;
  FILE *fp;
  int c;

  if (NULL == (fp = fopen(ctermid(NULL), "r+"))) {
    /* Couldn't get the controlling tty... */
    return -1;
  }

  setbuf(fp, NULL);

  /* Block signals; don't want to interrupt before we restore echo. */
  sigemptyset(&sig);
  sigaddset(&sig, SIGINT);
  sigaddset(&sig, SIGTSTP);
  sigprocmask(SIG_BLOCK, &sig, &sigsave);
  /* Save existing terminal attributes, then stop echo. */
  tcgetattr(fileno(fp), &termsave);
  term = termsave;
  term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
  tcsetattr(fileno(fp), TCSAFLUSH, &term);

  /* Put out the prompt */
  fputs(prompt, fp);

  ptr = pass_buf;
  while ((c=getc(fp)) != EOF && c!='\n') {
    if (ptr < &pass_buf[buf_len-1]) {
      *ptr++ = c;
    }
  }
  *ptr=0; /* NULL terminate */
  putc('\n', fp);

  /* Restore old terminal attributes. */
  tcsetattr(fileno(fp), TCSAFLUSH, &termsave);

  /* Restore old signal settings. */
  sigprocmask(SIG_SETMASK, &sigsave, NULL);

  /* Don't need the terminal anymore. */
  fclose(fp);

  return 0;
#endif
}
