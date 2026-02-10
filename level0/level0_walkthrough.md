# Level0 - Walkthrough

## Objectif
Trouver l'argument correct pour lancer un shell avec privilèges level1.

---

## Étape 1 : Connexion

```bash
ssh level0@localhost -p 4242
# Mot de passe : level0
```

---

## Étape 2 : Reconnaissance

```bash
ls -la
```

Observer le binaire `level0` avec le bit SUID.

Tester le programme :
```bash
./level0
# Segmentation fault

./level0 test
# No !
```

---

## Étape 3 : Analyse (optionnel)

### Avec GDB
```bash
gdb level0
(gdb) disas main
```

Observer la comparaison avec `0x1a7`.

Convertir en décimal :
```bash
python -c "print(0x1a7)"
# 423
```

---

## Étape 4 : Exploitation

```bash
./level0 423
# Shell ouvert
cat /home/user/level1/.pass
```

---

## Étape 5 : Passer au niveau suivant

```bash
exit
su level1
# Mot de passe : 1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

---

## Flag
```
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```
