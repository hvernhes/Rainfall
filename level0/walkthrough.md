# Level0 - Walkthrough

## Objectif
Trouver le bon argument à passer au binaire `level0` pour obtenir un shell avec les privilèges de `level1`.

---

## Étape 1 : Reconnaissance

### Connexion et exploration
```bash
ssh level0@192.168.1.45 -p 4242
# Mot de passe : level0

ls -la
```

**Observation :**
```
-rwsr-x---+ 1 level1 users  747441 Mar  6  2016 level0
```

- Le bit **SUID** (`s`) est présent → le binaire s'exécute avec les droits de `level1`
- Propriétaire : `level1`

### Test initial
```bash
./level0
# Résultat : Segmentation fault (core dumped)

./level0 42
# Résultat : No !

./level0 test
# Résultat : No !
```

**Conclusion :** Le programme attend un argument spécifique (probablement un nombre).

---

## Étape 2 : Analyse statique avec GDB

### Désassembler la fonction main
```bash
gdb level0
(gdb) disas main
```

**Instructions clés :**
```asm
0x08048ed4 <+20>:    call   0x8049710 <atoi>
0x08048ed9 <+25>:    cmp    $0x1a7,%eax
0x08048ede <+30>:    jne    0x8048f58 <main+152>
```

### Interprétation
1. **`call atoi`** : Convertit `argv[1]` en entier
2. **`cmp $0x1a7,%eax`** : Compare le résultat avec `0x1a7`
3. **`jne 0x8048f58`** : Saute vers le message "No !" si différent

---

## Étape 3 : Conversion hexadécimale → décimale

https://www.rapidtables.com/convert/number/hex-to-decimal.html

**Le nombre attendu est 423.**

---

## Étape 4 : Exploitation

### Lancer le binaire avec le bon argument
```bash
./level0 423
```

**Résultat :** Un shell s'ouvre (`$` prompt)

### Vérifier les privilèges
```bash
$ whoami
level1

$ id
uid=2030(level1) gid=2030(level1) groups=...
```

✅ Nous avons maintenant les droits de `level1` !

---

## Étape 5 : Récupération du flag
```bash
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

---

## Étape 6 : Passage au niveau suivant
```bash
$ exit
level0@RainFall:~$ su level1
Password: 1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
level1@RainFall:~$ 
```

✅ **Level0 complété !**

---

## Explication technique

### Pourquoi ça fonctionne ?

1. **Bit SUID** : Le binaire s'exécute avec les droits de son propriétaire (`level1`)
2. **Vérification faible** : Simple comparaison d'un nombre
3. **Élévation de privilèges** : 
   - `getegid()` / `geteuid()` récupèrent les ID effectifs (level1)
   - `setresgid()` / `setresuid()` changent les privilèges réels
   - `execv("/bin/sh")` lance un shell avec ces privilèges

### Pourquoi le segfault sans argument ?

Le code fait `atoi(argv[1])` **sans vérifier** si `argc >= 2`.

Si aucun argument n'est fourni, `argv[1]` est `NULL` → accès mémoire invalide → **segfault**.

---

## Outils utilisés

- **GDB** : Désassemblage et analyse dynamique
- **Ghidra** : Décompilation pour comprendre la logique
- **Python/printf** : Conversion hexadécimale

---

## Flag
```
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```