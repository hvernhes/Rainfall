#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

int main(int argc,char **argv)

{
  int nb;
  char *shell[2];
  __uid_t uid;
  __gid_t gid;
  
  nb = atoi(argv[1]);
  if (nb == 0x1a7) {
    shell[0] = strdup("/bin/sh");
    shell[1] = NULL;
    gid = getegid();
    uid = geteuid();
    setresgid(gid,gid,gid);
    setresuid(uid,uid,uid);
    execv("/bin/sh",&shell);
  }
  else {
    fwrite("No !\n",1,5,(FILE *)stderr);
  }
  return 0;
}