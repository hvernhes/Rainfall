#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char c[68];  // Variable globale pour le flag

void m(void)
{
    time_t timestamp = time(NULL);
    printf("%s - %d\n", c, timestamp);  // Affiche le flag !
}

int main(int argc, char **argv)
{
    int *struct_a;
    void *buffer_a;
    int *struct_b;
    void *buffer_b;
    FILE *file;

    // Allocation 1 : Struct A
    struct_a = malloc(8);
    struct_a[0] = 1;              // Valeur
    buffer_a = malloc(8);         // Allocation 2 : Buffer A
    struct_a[1] = buffer_a;       // Pointeur vers Buffer A

    // Allocation 3 : Struct B
    struct_b = malloc(8);
    struct_b[0] = 2;              // Valeur
    buffer_b = malloc(8);         // Allocation 4 : Buffer B
    struct_b[1] = buffer_b;       // Pointeur vers Buffer B

    strcpy((char *)struct_a[1], argv[1]);  // ⚠️ Buffer overflow !
    strcpy((char *)struct_b[1], argv[2]);  // ⚠️ Écrit où struct_b[1] pointe

    file = fopen("/home/user/level8/.pass", "r");
    fgets(c, 68, file);           // Lit le flag dans c
    puts("~~");                   // ← On va détourner ça vers m()

    return 0;
}