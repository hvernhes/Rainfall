#include <stdio.h>
#include <stdlib.h>

int m;  // Variable globale, initialisée à 0

void v(void)
{
    char local_20c[520];
    
    fgets(local_20c, 0x200, stdin);
    printf(local_20c);  // ⚠️ Format string vulnerability !
    
    if (m == 0x40) {    // Si m == 64
        fwrite("Wait what?!\n", 1, 0xc, stdout);
        system("/bin/sh");
    }
}

int main(void)
{
    v();
    return 0;
}