# Rainfall - SSH & Commandes Utiles

## 🔌 Connexion SSH

```bash
# Connexion initiale
ssh level0@<IP> -p 4242
# Mot de passe : level0

# Changer de niveau (après avoir récupéré le .pass)
su level1
# Entrer le contenu du .pass comme mot de passe
```

---

## 📁 Transfert de fichiers

```bash
# Copier un fichier de la VM vers ta machine
scp -P 4242 level0@<IP>:/home/user/level0/fichier ./

# Copier un dossier entier de la VM vers ta machine
scp -P 4242 -r level0@<IP>:/home/user/level0/ ./

# Copier un fichier de ta machine vers la VM
scp -P 4242 ./fichier level0@<IP>:/tmp/
# ⚠️ Utiliser /tmp/ — le home directory n'est pas writeable
```

---

## 🚩 Flags

```bash
# Lire le .pass du niveau suivant (depuis le shell obtenu)
cat /home/user/level1/.pass

# Chemin général
cat /home/user/levelX/.pass
cat /home/user/bonusX/.pass
cat /home/user/end/.pass
```

---

## 🛠️ Commandes utiles sur la VM

```bash
# Trouver l'IP si pas visible au boot
ifconfig

# Vérifier les protections d'un binaire (ASLR, NX, canary, PIE...)
checksec --file=./levelX

# Afficher les variables d'environnement
env
printenv LANG

# Lancer un binaire avec environnement propre (adresses plus stables)
env -i ./levelX arg1

# Désassemblage et symboles
objdump -d ./levelX          # Désassemblage complet
objdump -R ./levelX          # Table de relocation (GOT)
nm ./levelX                  # Symboles
ltrace ./levelX arg1         # Appels aux fonctions libc
```

---

## 🔍 GDB - Référence rapide

```bash
gdb ./levelX

# Configuration
(gdb) set disassembly-flavor intel

# Désassembler
(gdb) disass main
(gdb) disass functionName

# Breakpoints
(gdb) b *main
(gdb) b *main+42
(gdb) b *0x08048xyz

# Exécution
(gdb) run arg1 arg2
(gdb) run $(python -c 'print "A"*100')
(gdb) continue
(gdb) ni                              # next instruction
(gdb) si                              # step into

# Inspecter la mémoire
(gdb) x/20x $esp                      # 20 mots hex depuis esp
(gdb) x/20s *((char**)environ)        # Variables d'environnement
(gdb) x $ebp-0x1008                   # Adresse relative à ebp
(gdb) info registers                  # Tous les registres

# Trouver l'offset EIP avec un pattern cyclique
(gdb) run $(python -c 'print "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9..."')
# Lire eip après segfault → identifier l'offset sur wiremask.eu
```

---

## 🐍 Python - Génération de payload

```bash
# Padding simple
python -c 'print "A" * 76'

# Adresse en little-endian
python -c 'print "A"*76 + "\x08\x04\x85\xab"'

# NOP sled + shellcode + padding + adresse
python -c 'print "\x90"*100 + "\x31\xc0..." + "A"*72 + "\xd0\xe6\xff\xbf"'

# En argument
./levelX $(python -c 'print "A"*76 + "\x08\x04\x85\xab"')

# Via pipe (stdin)
python -c 'print "A"*76 + "\x08\x04\x85\xab"' | ./levelX

# Maintenir stdin ouvert pour interagir avec le shell obtenu
(python -c 'print "payload"'; cat) | ./levelX
```

---

## 📌 Rappel structure du repo

```
levelX/
├── flag          ← contenu du .pass
├── source        ← code source reconstruit (C/C++)
├── walkthrough   ← étapes d'exploitation
└── Ressources/   ← fichiers annexes (scripts, notes GDB...)
```
