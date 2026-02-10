#include <stdio.h>
#include <stdlib.h>

void run(void)
{
    fwrite("Good... Wait what?\n", 1, 19, stdout);
    system("/bin/sh");
}

int main(void)
{
    char buffer[76];
    
    gets(buffer);  // Vulnérabilité : pas de vérification de taille
    
    return 0;
}