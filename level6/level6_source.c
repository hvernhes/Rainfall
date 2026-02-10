#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void m(void *param_1, int param_2, char *param_3, int param_4, int param_5)
{
  puts("Nope");
  return;
}

void n(void)
{
  system("/bin/cat /home/user/level7/.pass");
  return;
}

int main(int argc, char **argv)
{
  char *__dest;
  void (*puVar1)(void);
  
  __dest = malloc(0x40);
  puVar1 = malloc(4);
  *((void (**)(void))puVar1) = m;
  strcpy(__dest, argv[1]);
  (*puVar1)();
  return (0);
}
