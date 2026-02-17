#include <stdio.h>
#include <stdlib.h>

int m;  // Variable globale, initialisée à 0

void p(char *param)
{
    printf(param);  // ⚠️ Format string vulnerability !
}

void n(void)
{
    char local_20c[520];

    fgets(local_20c, 0x200, stdin);
    p(local_20c);

    if (m == 0x1025544) {   // Si m == 16930116
        system("/bin/cat /home/user/level5/.pass");
    }
}

int main(void)
{
    n();
    return 0;
}