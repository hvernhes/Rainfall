# Level1 - Buffer Overflow

## Vue d'ensemble

Level1 introduit le concept de **buffer overflow** classique. Le programme utilise la fonction dangereuse `gets()` qui ne vérifie pas la taille de l'input, permettant d'écraser la stack et de détourner le flux d'exécution vers une fonction cachée.

---

## Code source reconstruit
```c
#include <stdio.h>
#include <stdlib.h>

void run(void)
{
    fwrite("Good... Wait what?\n", 1, 19, stdout);
    system("/bin/sh");
}

int main(void)
{
    char buffer[76];
    
    gets(buffer);  // Vulnérabilité : pas de vérification de taille
    
    return 0;
}
```

---

## La vulnérabilité : gets()

### Pourquoi `gets()` est dangereux
```c
char buffer[76];
gets(buffer);  // ❌ Aucune limite de taille
```

La fonction `gets()` :
- Lit depuis stdin jusqu'à `\n` ou EOF
- **N'impose aucune limite** de taille
- Écrit directement en mémoire sans vérification
- Officiellement **deprecated** depuis C11 (2011)

### Alternative sécurisée
```c
char buffer[76];
fgets(buffer, sizeof(buffer), stdin);  // ✅ Limite à 76 octets
```

---

## Structure de la stack

### Organisation mémoire lors de l'appel à main
```
Adresses hautes
┌─────────────────────────┐
│  Arguments (argc, argv) │
├─────────────────────────┤
│  Adresse de retour (EIP)│  ← Cible : contrôler cette adresse (4 octets)
├─────────────────────────┤
│  EBP sauvegardé         │  ← Base pointer de la frame précédente (4 octets)
├─────────────────────────┤
│  buffer[76]             │  ← Notre buffer local (76 octets)
└─────────────────────────┘
Adresses basses (ESP)
```

### Calcul de l'offset

Pour atteindre l'adresse de retour (EIP) depuis le début du buffer :
- **Buffer** : 76 octets
- **EBP sauvegardé** : 4 octets
- **Total** : **80 octets**

Notre payload :
```
[80 octets de padding] + [adresse de destination]
```

---

## Concepts clés

### Buffer Overflow

**Définition :** Écriture au-delà des limites d'un buffer alloué, permettant d'écraser des données adjacentes en mémoire (variables locales, adresses de retour, pointeurs).

**Conséquence :** Contrôle du flux d'exécution en écrasant l'adresse de retour.

### EIP (Extended Instruction Pointer)

**Rôle :** Registre CPU contenant l'adresse de la **prochaine instruction** à exécuter.

**Exploitation :** En écrasant l'adresse de retour sur la stack, on contrôle la valeur d'EIP lors du `return`, redirigeant l'exécution vers l'adresse de notre choix.

### Fonction cachée

Une fonction présente dans le binaire mais **jamais appelée** dans le flux normal d'exécution. Dans un contexte CTF, c'est souvent une "backdoor" intentionnelle.

Ici, la fonction `run()` :
- Existe dans le binaire
- N'est jamais appelée par `main`
- Contient `system("/bin/sh")` qui nous donne un shell

### Bit SUID (Set User ID)

**Permission spéciale** qui fait qu'un binaire s'exécute avec les privilèges de son **propriétaire** plutôt que ceux de l'utilisateur qui le lance.

**Identification :**
```bash
-rwsr-s---+ 1 level2 users  5138  level1
   ^
   └─ 's' au lieu de 'x' = bit SUID activé
```

**Conséquence :** Le shell lancé par `system("/bin/sh")` hérite des privilèges de `level2`.

---

## Architecture x86 : Little-endian

### Ordre des octets en mémoire

En architecture x86, les valeurs multi-octets sont stockées en **little-endian** : l'octet de poids **faible** est stocké en **premier**.

**Exemple :**

L'adresse `0x08048444` doit être écrite en mémoire comme :
```
\x44\x84\x04\x08
```

**Visualisation :**
```
Adresse mémoire:  [0x100] [0x101] [0x102] [0x103]
Contenu:            0x44    0x84    0x04    0x08
                    ^^^^                    ^^^^
                poids faible            poids fort
```

### Pourquoi little-endian ?

Raisons historiques (architecture Intel) :
- Simplifie les opérations arithmétiques sur des valeurs de tailles variables
- Permet de lire un `short` (2 octets) ou un `int` (4 octets) à partir de la même adresse

---

## Scénarios d'exécution

### Scénario normal (sans overflow)
```c
char buffer[76];
gets(buffer);  // User entre "hello"
return;        // Retourne à l'appelant de main
```

**Stack :**
```
┌──────────────┐
│ 0x080484a0   │  ← Adresse de retour normale (vers _start ou __libc_start_main)
├──────────────┤
│ 0xbffff7d8   │  ← EBP sauvegardé
├──────────────┤
│ "hello\0..." │  ← buffer[76]
└──────────────┘
```

Le `return` charge `0x080484a0` dans EIP → exécution continue normalement.

---

### Scénario avec buffer overflow
```c
char buffer[76];
gets(buffer);  // User entre 80 'A' + adresse de run()
return;        // Retourne vers run() !
```

**Stack après overflow :**
```
┌──────────────┐
│ 0x08048444   │  ← Adresse écrasée (pointe vers run)
├──────────────┤
│ 0x41414141   │  ← EBP écrasé par 'AAAA'
├──────────────┤
│ AAAA...AAAA  │  ← buffer rempli de 76 'A'
└──────────────┘
```

Le `return` charge maintenant `0x08048444` dans EIP → saut vers `run()` !

---

## Construction du payload

### Étape 1 : Padding de 80 octets

Remplir le buffer (76 octets) + EBP sauvegardé (4 octets) :
```
'A' × 80
```

### Étape 2 : Adresse de run en little-endian

Adresse : `0x08048444`  
Format little-endian : `\x44\x84\x04\x08`

### Étape 3 : Assemblage
```bash
printf 'AAAA...AAAA\x44\x84\x04\x08'
        ^^^^^^^^^^^  ^^^^^^^^^^^^^^^^
        80 octets    Adresse de run
```

### Étape 4 : Garder stdin ouvert

**Problème :** Le pipe ferme stdin après l'envoi du payload. Le shell reçoit immédiatement EOF et se termine.

**Solution :** Utiliser `cat` pour garder stdin ouvert et permettre l'interaction avec le shell :
```bash
(printf '...'; cat) | ./level1
```

---

## Pourquoi ça fonctionne ?

### 1. Buffer overflow

`gets()` permet d'écrire au-delà des 76 octets du buffer.

### 2. Écrasement de l'adresse de retour

En écrivant 80 octets de padding + 4 octets d'adresse, on écrase l'adresse de retour stockée sur la stack.

### 3. Contrôle d'EIP

Lors du `return` de `main`, le CPU charge notre adresse dans EIP au lieu de l'adresse normale.

### 4. Saut vers run()

Le programme saute vers `run()` qui exécute `system("/bin/sh")`.

### 5. Élévation de privilèges

Le binaire a le bit SUID de `level2`, donc le shell hérite de ces privilèges.

---

## Détails techniques

### Pourquoi le segfault avec trop de 'A' ?
```bash
python -c "print('A' * 100)" | ./level1
Segmentation fault
```

**Explication :**
1. On écrit 100 'A', dont les 4 derniers écrasent l'adresse de retour
2. L'adresse de retour devient `0x41414141` (AAAA en ASCII)
3. Le `return` tente de sauter vers `0x41414141`
4. Cette adresse n'existe pas ou n'est pas mappée → **Segmentation fault**

### Comment trouver l'offset exact ?

**Méthode incrémentale :**

Tester avec des marqueurs uniques :
```gdb
(gdb) run
AAAA...AAAABBBB
^D
```

Si EIP = `0x42424242` (BBBB), on sait que les 4 'B' ont écrasé l'adresse de retour, et on calcule l'offset des 'A' précédents.

---

## Protections modernes (absentes ici)

Ce type d'attaque est aujourd'hui mitigé par plusieurs protections :

### Stack Canaries

Valeur aléatoire placée entre les variables locales et l'adresse de retour. Si elle est modifiée, le programme s'arrête avant le `return`.
```
┌──────────────┐
│ Adresse ret  │
├──────────────┤
│ CANARY       │  ← Valeur vérifiée avant return
├──────────────┤
│ buffer       │
└──────────────┘
```

### DEP/NX (Data Execution Prevention)

Marque certaines zones mémoire (comme la stack) comme **non-exécutables**, empêchant l'exécution de shellcode injecté.

### ASLR (Address Space Layout Randomization)

Randomise les adresses de la stack, heap, et libc à chaque exécution, rendant les adresses fixes inutilisables.

### PIE (Position Independent Executable)

Le code du binaire lui-même est chargé à une adresse aléatoire.

**Dans Rainfall :** Ces protections sont **désactivées** pour faciliter l'apprentissage.

---

## Outils utilisés

### GDB (GNU Debugger)

**Commandes essentielles :**
```gdb
info functions       # Liste toutes les fonctions
print run            # Affiche l'adresse de run
disas main           # Désassemble main
run                  # Exécute le programme
info registers       # Affiche les registres (EIP, ESP, etc.)
x/20wx $esp          # Examine 20 words à partir de ESP
```

### Ghidra

Décompilateur qui transforme le binaire en pseudo-code C lisible.

**Workflow :**
1. Importer le binaire
2. Analyser automatiquement
3. Explorer les fonctions
4. Lire le code décompilé

### printf (shell builtin)

**Pourquoi pas `echo` ?**
```bash
echo '\x44'      # Affiche littéralement : \x44 (4 caractères)
printf '\x44'    # Interprète et affiche l'octet 0x44 (1 octet)
```

`printf` interprète correctement les séquences d'échappement hexadécimales, essentiel pour construire des payloads binaires.

---

## Résumé de l'exploitation

1. **Vulnérabilité** : `gets()` sans limite de taille
2. **Découverte** : Fonction cachée `run()` contenant `system("/bin/sh")`
3. **Offset** : 80 octets pour atteindre l'adresse de retour
4. **Payload** : 80 octets de padding + adresse de `run()` (little-endian)
5. **Exploitation** : Buffer overflow → Contrôle d'EIP → Saut vers `run()` → Shell avec privilèges level2
6. **Récupération** : Lecture du flag dans `/home/user/level2/.pass`

---

## Concepts pour la suite

Les prochains niveaux introduiront probablement :
- **Return-to-libc** : Sauter vers des fonctions de la libc
- **ROP (Return-Oriented Programming)** : Chaîner des gadgets
- **Format string attacks** : Exploiter `printf(user_input)`
- **Heap overflow** : Exploiter des buffers alloués dynamiquement
- **Bypasser des protections** : Canaries, ASLR, etc.

---

## Ressources

- [Smashing The Stack For Fun And Profit](http://phrack.org/issues/49/14.html) - Article fondateur (1996)
- [Buffer Overflow Attack - OWASP](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
- [x86 Assembly Guide](https://www.cs.virginia.edu/~evans/cs216/guides/x86.html)
- [GDB Cheat Sheet](https://darkdust.net/files/GDB%20Cheat%20Sheet.pdf)