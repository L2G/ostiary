#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

/* Meant to be run as a command, makes sure that the uid/gid
   code is working properly. */

int main(int argc, char *argv[])
{
  uid_t my_uid;
  gid_t my_gid;
  FILE *fp;

  my_uid = getuid();
  my_gid = getgid();

  if (NULL == (fp = fopen("/tmp/ostiary/ostcmds.log", "a+"))) {
    fprintf(stderr, "Error opening output file!\n");
    return -1;
  }
  stderr = fp;

  fprintf(fp, "I'm running as %d:%d.\n", my_uid, my_gid);

  /* Makes sure commands can't easily recover root... */
  if (!my_uid) {
    /* We're not root, so let's try. */
    if (setuid(0)) {
      fprintf(fp, "Could not set uid to '0': ", errno);
      perror("");
    } else {
      fprintf(fp, "Uh oh, got root!\n", errno);
    }
  }

  fclose(fp);

  return 0;
}
