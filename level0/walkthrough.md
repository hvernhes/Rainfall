# Level0 - Walkthrough

## Objectif
Exploiter une valeur magique hard-codée dans un binaire SUID pour obtenir un shell level1.

---

## Étapes d'exploitation

### 1. Reconnaissance
```bash
ls -la
# -rwsr-x---+ 1 level1 users  747441 Mar  6  2016 level0
# ⚠️ Bit SUID actif → s'exécute avec les droits de level1

./level0
# Segmentation fault

./level0 42
# No !
```

### 2. Analyse GDB
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

### 3. Conversion hexadécimale
```
0x1a7 = (1 × 256) + (10 × 16) + (7 × 1) = 423
```

### 4. Exploitation
```bash
./level0 423
```

**Résultat :** Shell obtenu avec les droits de level1.

### 5. Vérification
```bash
$ whoami
level1

$ id
uid=2030(level1) gid=2030(level1)
```

### 6. Récupération du flag
```bash
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

### 7. Passage au niveau suivant
```bash
$ exit
level0@RainFall:~$ su level1
Password: 1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
level1@RainFall:~$ 
```

---

## Flag
```
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

## Type de vulnérabilité
- Logic flaw (valeur magique hard-codée)
- SUID privilege escalation