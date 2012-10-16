/* find_hash.c - Try to break an Ostiary hash, dictionary-style.
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
#include <string.h> /* strchr(), etc. */
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "ost.h"
#include "ost_hash.h"

/* I am not proud of this code. I just hacked it together to get
   a vague idea of how hard it is to crack a passphrase. Someone
   seriously interested in attacking could definitely do much,
   much better. DO NOT rely on this to check the security of your
   passphrases. */

typedef enum {
 DUMB=0,
 BRUTE,
 WORDFILE
} OST_BREAK_ALG;

typedef enum {
 LOWER=0,
 UPPER,
 CAPPED,
 MIXED
} OST_ASCII_STATE;

typedef struct OST_WORD_STATE {
  struct OST_WORD_STATE *next;
  int len;
  int capsplace;
  int pre_punc;
  int post_punc;
  OST_ASCII_STATE ascii;
  char *word;
} OST_Word_State;

OST_BREAK_ALG g_alg;
unsigned char g_seed_hash[HASH_BIN_SIZE], g_cmd_hash[HASH_BIN_SIZE];
unsigned int g_interval;
unsigned int g_use_v1;
char *g_words;
OST_Word_State *g_word_state;

/* Used in the 'BRUTE' algorithm. */
#define MIN_PRINTABLE_ASCII 32
#define MAX_PRINTABLE_ASCII 126

/* Use regular Unix getopt. */
extern char *optarg;
extern int optind, opterr, optopt;

#if 0
/* Really thorough. */
char g_punc_list[] = {'!','@','#','$','%','^','&','*','(',')',
                      '_','-','=','+','[',']','{','}','\\','|',
                      ':',';','\'','\"',',','<','>','.','/','?',
                      '`','~',' ','\t',0};
#else
/* Most likely stuff. */
char g_punc_list[] = {' ','.','!','?','\"','\'','`',',',':',';',
                      '-','(',')', 0};
#endif
int g_punc_list_len;

/* Turn an ASCII rep of an MD5 hash to binary */
int De_ASCII_Hash(char *input, unsigned char *out_hash)
{
  int i, tempint;
  char str[9];

  memset(str, 0, 9);

  if (32 > strlen(input)) {
    return -1;
 }

  for (i=0; i<4; i++) {
    memcpy(str, input+i*8, 8);
    //    printf("%s : ", str);
    sscanf(str, "%x", &tempint);
    //    printf("%x : ", tempint);
#ifndef WORDS_BIGENDIAN
    tempint = htonl(tempint);
#endif
    *(int *)(out_hash+i*4) = tempint;
    //printf("%x", *(int *)(out_hash+i*4));
  }
  //printf("\n");
  return 0;
}

/* Return the first word in the list. */
char *Get_First_Word()
{
  return g_words;
}

/* Return the next word in the list. */
char *Get_Next_Word(char *current)
{
  char *temp;

  if (!strlen(current)) {
    return NULL; /* Ain't no more. */
  }

  /* Scoot past next null byte. */
  while(*(current++)) {
    /* Empty loop. */
  }

  return current; /* Next word... */
}

/* Assumes a big list of words, one per line, no whitespace beyond
   linefeeds. /usr/dict/words fulfills this... */
int Get_Word_File(char *file_name)
{
  int i, file_d;
  off_t file_size;

  /* Open it. */
  if (0 > (file_d = open(file_name, O_RDONLY))) {
    perror("Opening word file: ");
    return -1;
  }

  /* Get the size. */
  if (-1 == (file_size = lseek(file_d, 0, SEEK_END))) {
    perror("Getting word file size: ");
    return -1;
  }

  printf("File size is: %d\n", file_size);

  /* Allocate buffer. */
  if (NULL == (g_words = calloc(1, file_size+2))) {
    printf("Error allocating word buffer!\n");
    return -1;
  }

  /* Seek back to beginning. */
  if (-1 == lseek(file_d, 0, SEEK_SET)) {
    perror("Seeking to beginning ");
    return -1;
  }

  /* Read in the data. */
  if (file_size > read(file_d, g_words, file_size)) {
    perror("Did not read all words: ");
    return -1;
  }

  close(file_d);

  //printf("%s", g_words);

  /* Replace the newlines with nulls, make lowercase. */
  for (i=0; i<file_size; i++) {
    if ('\n' == g_words[i]) {
      g_words[i] = 0;
    } else {
      g_words[i] = tolower(g_words[i]);
    }
  }

  /* Now, we've got a great big pile of NULL-terminated strings,
     with at least one extra NULL at the end to signal 'no more
     words'. */

  if (NULL == (g_word_state = calloc(1, sizeof(OST_Word_State)))) {
    printf("Error allocating word state!\n");
    return -1;    
  }

  g_word_state->word = Get_First_Word();
  g_word_state->len = strlen(g_word_state->word);
  printf("First word: '%s', len: %d.\n",
         g_word_state->word, g_word_state->len);
  g_punc_list_len = strlen(g_punc_list);
  printf("punc list: '%s', len: %d.\n", g_punc_list, g_punc_list_len);
  return 0;
}

/* -c cmd hash, -s seed hash [ [-b | -d] | [-w words file] ] [-v (use old hash) ] */
int Get_Cmdline_Options(int argc, char *argv[])
{
  char *cur_str_pos;
  struct hostent *hent;
  /* Use getopt(), set up any non-default values. */
  int c, error=0;
  int s_found = 0, c_found = 0, b_found=0, d_found=0, w_found=0,
    i_found = 0, v_found = 0;

  /* Initialize cfg file name. */

  while (EOF != (c = getopt(argc, argv, "s:c:i:w:bdv"))) {
    switch (c) {
    case 'i':
      if (i_found) {
        /* Hey! We already did this option! */ 
        error = 1;
      } else {
        /* Okay, we've got a seed. */
        i_found = 1;
        g_interval = atoi(optarg);
      }
      break;
    case 's':
      if (s_found) {
        /* Hey! We already did this option! */ 
        error = 1;
      } else {
        /* Okay, we've got a seed. */
        s_found = 1;
        error = De_ASCII_Hash(optarg, g_seed_hash);
      }
      break;
    case 'c': 
      if (c_found) {
        /* Hey! We already did this option! */
        error = 1;
      } else {
        c_found = 1;
        error = De_ASCII_Hash(optarg, g_cmd_hash);
      }
      break;
    case 'w':
      if (w_found) {
        /* Hey! We already did this option! */ 
        error = 1;
      } else {
        b_found = w_found = d_found = 1;
        if (Get_Word_File(optarg)) {
          exit(EXIT_FAILURE);
        }
        g_alg = WORDFILE;
      }
      break;
    case 'v':
      if (v_found) {
        /* Hey! We already did this option! */ 
        error = 1;
      } else {
        /* Okay, alg chosedn. */
        v_found = 1;
        g_use_v1 = 1;
      }
      break;
    case 'b':
      if (b_found) {
        /* Hey! We already did this option! */ 
        error = 1;
      } else {
        /* Okay, alg chosedn. */
        b_found = w_found = d_found = 1;
        g_alg = BRUTE;
    case 'd':
      if (d_found) {
        /* Hey! We already did this option! */ 
        error = 1;
      } else {
        /* Okay, alg chosen. */
        b_found = w_found = d_found = 1;
        g_alg = DUMB;
      }
      break;
    default:
      error = 1; /* something's wrong. */
      break;
    }
    if (error) {
      /* Some kind of command line error. */
      printf("usage: %s -s seed hash -c cmd hash [-i interval] "
             "[ [-b | -d] | [-w wordfile] ]\n", argv[0]);
      return -1;
    }
  }
  return 0; /* All's well that ends well */
}

/* Brick stupid. Basically, take 'guess' and increment it. Sort of
   reverse bignum math. Guaranteed to hit, eventually, but will take
   Vast amounts of time. */
void Guess_Dumb(unsigned char *guess)
{
  int i;

  for (i=0; i<MAX_SECRET_SIZE; i++) {
    if (CHAR_MAX > guess[i]) {
      guess[i]++;
      return;
    } else {
      guess[i] = 0;
    }
  }
}

/* Like 'Dumb', but tries to limit chars to just printable ASCII.
   (Doesn't include tab, cr, lf either). About twice as fast as
   the above 'dumb' algorithm, but that's not saying much, and
   it's not guaranteed to find a clever password. */
void Guess_Brute(unsigned char *guess)
{
  int i;

  for (i=0; i<MAX_SECRET_SIZE; i++) {
    if (guess[i]) {
      if (MAX_PRINTABLE_ASCII > guess[i]) {
        guess[i]++;
        return;
      } else {
        guess[i] = MIN_PRINTABLE_ASCII;
      }
    } else {
      /* Start out with ' '. */
      guess[i] = MIN_PRINTABLE_ASCII;
      return;
    }
  }
}

/* Use words from a file to try to assemble passphrases. Will also
   throw in some punctuation. Probably more likely to find a passphrase
   before the heat death of the universe, but a single misspelling
   will screw it up. */
void Guess_Word_File(unsigned char *guess)
{
  int i, cur_len;
  OST_Word_State *temp_ws = g_word_state;
  char temp_str[MAX_SECRET_SIZE];

  memset(guess, 0, MAX_SECRET_SIZE);

  /* Increment through all available options. */
  while (temp_ws) {
    /* Generate the latest guess. */
    if (temp_ws->pre_punc < g_punc_list_len) {
      temp_ws->pre_punc++;
      break;
    } else {
      temp_ws->pre_punc = 0;
    }

    if (temp_ws->ascii < MIXED) {
      temp_ws->ascii++;
      break;
    } else {
      if (temp_ws->capsplace < temp_ws->len) {
        temp_ws->capsplace++;
        break;
      } else {
        temp_ws->capsplace=0;
        temp_ws->ascii = LOWER;
      }
    }

    if (temp_ws->post_punc < g_punc_list_len) {
      temp_ws->post_punc++;
      break;
    } else {
      temp_ws->post_punc = 0;
      temp_ws = temp_ws->next;
    }
  }

  if (!temp_ws) {
    /* Okay, all the existing words have been through all the
       variations. */

    /* Increment words. */
    temp_ws = g_word_state;
    while (temp_ws) {
      if (temp_ws->word = Get_Next_Word(temp_ws->word)) {
        temp_ws->len = strlen(temp_ws->word);
        break;
      } else {
        temp_ws->word = Get_First_Word();
        temp_ws->len = strlen(temp_ws->word);
        temp_ws = temp_ws->next;
      }
    }

    if (!temp_ws) {
      /* Geez, they all rolled over, too. Add a new one. */

      /* Find end. */
      temp_ws = g_word_state;
      while (temp_ws->next) {
        temp_ws = temp_ws->next;
      }

      /* Stick new one on end. */
      if (NULL == (temp_ws->next = calloc(1, sizeof(OST_Word_State)))) {
        printf("Out of memory!\n");
        exit(EXIT_FAILURE);
      }
      temp_ws->next->word = Get_First_Word();
    }
  }

  /* Generate actual guess based on current state. */
  for (cur_len=0,temp_ws=g_word_state;
       temp_ws && cur_len < MAX_SECRET_SIZE; temp_ws = temp_ws->next) {

    /* Pre-punctuation */
    if (g_punc_list[temp_ws->pre_punc]) {
      temp_str[1]=0;
      temp_str[0] = g_punc_list[temp_ws->pre_punc];
      //printf("Appending '%s'.\n", temp_str); 
      strncat(guess, temp_str, MAX_SECRET_SIZE-cur_len);
      cur_len++;
    }

    /* Put the word in current form */
    memset(temp_str, 0, MAX_SECRET_SIZE);
    switch(temp_ws->ascii) {
    case LOWER:
      strncat(temp_str, temp_ws->word, MAX_SECRET_SIZE-cur_len);
      break;
    case UPPER:
      strncat(temp_str, temp_ws->word, MAX_SECRET_SIZE);
      temp_str[0] = toupper(temp_str[0]);
      break;
    case CAPPED:
      strncat(temp_str, temp_ws->word, MAX_SECRET_SIZE);
      for (i=0; i<strlen(temp_str); i++) {
        temp_str[i] = toupper(temp_str[i]);
      }
      break;
    case MIXED:
      strncat(temp_str, temp_ws->word, MAX_SECRET_SIZE);
      temp_str[temp_ws->capsplace] = toupper(temp_str[temp_ws->capsplace]);
      break;
    }
    //printf("Appending '%s'.\n", temp_str); 
    strncat(guess, temp_str, MAX_SECRET_SIZE-cur_len);
    cur_len += temp_ws->len;

    /* Post-punctuation */
    if (g_punc_list[temp_ws->post_punc]) {
      temp_str[1]=0;
      temp_str[0] = g_punc_list[temp_ws->post_punc];
      //printf("Appending '%s'.\n", temp_str); 
      strncat(guess, temp_str, MAX_SECRET_SIZE-cur_len);
      cur_len++;
    }
  }
}

int Find_Hash_Init(int argc, char *argv[])
{
  /* Clear all the vars. */
  memset(g_seed_hash, 0, HASH_BIN_SIZE);
  memset(g_cmd_hash, 0, HASH_BIN_SIZE);

  g_use_v1 = 0;
  g_interval = 10000;

  /* Get the command-line options */
  if (Get_Cmdline_Options(argc, argv)) {
    fprintf(stderr, "Error parsing command-line options!\n");
    return -1;
  }

  /* Sanity-check the values. */

  /* Gotta have seed hash. */
  if (!g_seed_hash[0]) {
    fprintf(stderr, "Seed hash not set!\n");
    return -1;
  }

  /* Gotta have command hash. */
  if (!g_cmd_hash[0]) {
    fprintf(stderr, "Command hash not set!\n");
    return -1;
  }

  /* Gotta have valid port. */
  if (!g_interval) {
    fprintf(stderr, "Interval set to zero!\n");
    return -1;
  }

  /* Didn't return before now. All must be well. */
  return 0;
}

int main(int argc, char *argv[])
{
  unsigned long i;
  unsigned char current_hash[HASH_BIN_SIZE];
  unsigned char current_guess[MAX_SECRET_SIZE];
  char hash_out_buf[HASH_TEXT_SIZE]; /* for debug output */

  /* Init global vars, read configs, etc. */
  if (Find_Hash_Init(argc, argv)) {
    fprintf(stderr, "Problem in initialization, aborting!\n");
    return -1;
  }

  memset(current_guess, 0, MAX_SECRET_SIZE);

  Print_Hash(g_seed_hash, hash_out_buf, HASH_TEXT_SIZE);
  printf("Seed hash: '%s'.\n", hash_out_buf);
  Print_Hash(g_cmd_hash, hash_out_buf, HASH_TEXT_SIZE);
  printf("Command hash: '%s'.\n", hash_out_buf);

  /* Will try four-billion-odd guesses. More on 64-bit machines... */
  i=0;
  do {
    /* Generate the next guess. */
    switch (g_alg) {
    case BRUTE:
      Guess_Brute(current_guess);
      break;
    case DUMB:
      Guess_Dumb(current_guess);
      break;
    case WORDFILE:
      Guess_Word_File(current_guess);
      break;
    default:
      printf("Internal error, bailing.\n");
      return EXIT_FAILURE;
    }

    /* Compute the hash. */
    if (g_use_v1) {
      Do_Hash_Ver1(g_seed_hash, HASH_BIN_SIZE,
              current_guess, MAX_SECRET_SIZE, current_hash);
    } else {
      Do_Hash_Ver2(g_seed_hash, HASH_BIN_SIZE,
              current_guess, MAX_SECRET_SIZE, current_hash);
    }

    /* See if we've won lotto... */
    if (!memcmp(current_hash, g_cmd_hash, HASH_BIN_SIZE)) {
      /* Success! */
      printf("Guess %d matches, secret is '%s'!\n", i, current_guess);
      return EXIT_SUCCESS;
    }

    /* User feedback... */
    if (!(i%g_interval)) {
      printf("Guess #%d: %s\n", i, current_guess);
    }
  } while(++i);

  printf("Over four billion guesses and zip.\n");
  return EXIT_SUCCESS;
}
