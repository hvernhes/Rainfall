# Sur ta machine Linux/Mac
cat > level0_README.md << 'EOF'
# Level0 - README Pédagogique

## 🎯 Objectif
Exploiter une **faille logique combinée au bit SUID** pour obtenir un shell avec les privilèges de `level1`.

---

## 🔍 Reconnaissance

### Permissions du fichier
```bash
$ ls -l level0
-rwsr-x---+ 1 level1 users  747441 Mar  6  2016 level0
    ^
    └─ Bit SUID actif
```

**Observation clé** : Le binaire s'exécute avec les droits de `level1` (propriétaire) grâce au bit SUID.

### Tests comportementaux
```bash
$ ./level0
Segmentation fault (core dumped)

$ ./level0 42
No !

$ ./level0 test
No !
```

**Hypothèse** : Le programme attend un argument numérique spécifique.

---

## 🛠️ Analyse technique

### Code décompilé (Ghidra)
```c
void main(int argc, char **argv)
{
    int input;
    char *shell_args[2];
    gid_t egid;
    uid_t euid;
    
    input = atoi(argv[1]);  // ⚠️ Pas de vérification de argc !
    
    if (input == 423) {     // 0x1a7 en hexadécimal
        shell_args[0] = "/bin/sh";
        shell_args[1] = NULL;
        
        egid = getegid();
        euid = geteuid();
        
        setresgid(egid, egid, egid);
        setresuid(euid, euid, euid);
        
        execv("/bin/sh", shell_args);
    } else {
        fwrite("No !\n", 1, 5, stderr);
    }
}
```

### Analyse GDB
```bash
$ gdb level0
(gdb) disas main
```

**Instructions critiques** :
```asm
0x08048ed4 <+20>:    call   0x8049710 <atoi>
0x08048ed9 <+25>:    cmp    $0x1a7,%eax
0x08048ede <+30>:    jne    0x8048f58 <main+152>
```

**Calcul de la valeur attendue** :
```
0x1a7 = (1 × 256) + (10 × 16) + (7 × 1) = 423
```

---

## 💣 Vulnérabilités identifiées

### 1. NULL Pointer Dereference
**Code vulnérable** :
```c
int input = atoi(argv[1]);  // argv[1] peut être NULL si argc == 1
```

**Explication** :
- Sans argument, `argv[1]` vaut `NULL`
- `atoi()` tente de lire à l'adresse `0x00000000`
- Accès mémoire invalide → **SIGSEGV**

### 2. Logic Flaw (Valeur magique hard-codée)
**Code vulnérable** :
```c
if (input == 423) {  // Valeur facilement trouvable
    // Lance un shell
}
```

**Explication** :
- La valeur `0x1a7` (423) est visible dans le code assembleur
- Aucune obscurcissement ni vérification supplémentaire
- Simple comparaison directe

### 3. SUID Privilege Escalation
**Mécanisme** :
```c
egid = getegid();  // Récupère l'EGID effectif (level1)
euid = geteuid();  // Récupère l'EUID effectif (level1)

setresgid(egid, egid, egid);  // Force RGID=EGID=SGID
setresuid(euid, euid, euid);  // Force RUID=EUID=SUID

execv("/bin/sh", shell_args);  // Lance le shell
```

**Explication** :
- Le bit SUID donne `EUID = level1`
- Par défaut, `/bin/sh` détecte le SUID et drop les privilèges
- `setresuid(euid, euid, euid)` force `RUID = EUID` → le shell ne détecte plus de différence → ne drop pas

---

## 🔑 Concepts clés

### Le bit SUID
```
-rwsr-x---
    ^
    └─ 's' = SUID bit
```

**Fonctionnement** :
- Le binaire s'exécute avec les **droits du propriétaire** (level1)
- Pas avec les droits de celui qui le lance (level0)

### Les 3 types d'UID sous Linux

| Type | Nom | Description |
|------|-----|-------------|
| **RUID** | Real UID | Qui a lancé le processus |
| **EUID** | Effective UID | Privilèges effectifs (utilisé pour les permissions) |
| **SUID** | Saved UID | Sauvegarde pour revenir en arrière |

**Dans notre cas** :
```
Avant ./level0 :
  RUID = level0
  EUID = level0
  SUID = level0

Pendant ./level0 (grâce au SUID bit) :
  RUID = level0
  EUID = level1  ← Permet de lire /home/user/level1/.pass
  SUID = level1

Après setresuid(euid, euid, euid) :
  RUID = level1  ← Changé !
  EUID = level1
  SUID = level1
```

### Conversion hexadécimale
```
0x1a7 → decimal

Position : 16²   16¹   16⁰
Chiffre  :  1     a     7
Valeur   : 256   10     1

Calcul : (1 × 256) + (10 × 16) + (7 × 1) = 423
```

---

## 🚀 Exploitation

### Payload
```bash
$ ./level0 423
```

### Vérification
```bash
$ whoami
level1

$ id
uid=2030(level1) gid=2030(level1) groups=2030(level1),100(users)
```

### Récupération du flag
```bash
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

---

## 📝 Classification

**Type de vulnérabilités** :
- **CWE-476** : NULL Pointer Dereference
- **CWE-798** : Use of Hard-coded Credentials
- **CWE-250** : Execution with Unnecessary Privileges

---

## 🎓 Résumé

1. **Faille** : Valeur magique hard-codée (423) + Bit SUID
2. **Exploitation** : Passer `423` comme argument
3. **Résultat** : Shell avec les privilèges de `level1`
4. **Flag** : `1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a`
EOF