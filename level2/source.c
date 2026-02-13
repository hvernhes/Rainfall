#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void p(void)
{
    char buffer[76];
    unsigned int ret_addr;
    
    fflush(stdout);
    gets(buffer);
    
    // Lecture de la saved return address sur la stack
    ret_addr = *(unsigned int *)(__builtin_frame_address(0) + 4);
    
    // Protection anti-stack : bloque adresses >= 0xb0000000
    if ((ret_addr & 0xb0000000) == 0xb0000000) {
        printf("(%p)\n", (void *)ret_addr);
        _exit(1);
    }
    
    puts(buffer);
    strdup(buffer);  // Copie buffer sur le heap
}

int main(void)
{
    p();
    return 0;
}