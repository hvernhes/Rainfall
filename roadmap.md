# Rainfall - Roadmap Concise (Levels 0-9)

## 🎯 Level0 - Logic Flaw + SUID

### Objectif de la faille
Passer la valeur magique **423** en argument pour déclencher `system("/bin/sh")`.

### Étapes
1. **Trouver la valeur** → `0x1a7` = 423 en décimal
2. **./level0 423** → Condition vraie
3. **system("/bin/sh")** → Shell ✅

### Notions clés
- Bit SUID
- RUID/EUID/SUID
- `setresuid()`
- Valeur magique hard-codée

---

## 🎯 Level1 - Buffer Overflow + ret2func

### Objectif de la faille
Écraser la **saved return address** avec l'adresse de `run()` pour obtenir le shell.

### Étapes
1. **Pattern cyclique** → Trouver offset = 76 bytes
2. **Payload** : `"A"*76 + adresse_run()`
3. **ret** → EIP = adresse run()
4. **run()** → `system("/bin/sh")` → Shell ✅

### Notions clés
- Buffer overflow (stack)
- `gets()` vulnérable
- EIP (Instruction Pointer)
- Saved return address
- ret2func
- Pattern cyclique
- Little-endian
- Cat trick (`;cat`)

---

## 🎯 Level2 - Buffer Overflow + ret2heap + Shellcode

### Objectif de la faille
Injecter un **shellcode sur le heap** et y rediriger l'exécution.

### Étapes
1. **Pattern cyclique** → Offset = 80 bytes
2. **ltrace** → Trouver adresse heap = `0x0804a008`
3. **Payload** : `[shellcode][padding]["A"*59][adresse_heap]`
4. **strdup()** → Copie shellcode sur heap
5. **ret** → EIP = heap → Shellcode ✅

### Notions clés
- Protection anti-stack (`0xb...`)
- Heap vs Stack
- `strdup()`
- ret2heap
- Shellcode (21 bytes)
- `ltrace`

---

## 🎯 Level3 - Format String (simple)

### Objectif de la faille
Écrire **64** dans la variable globale `m` via format string.

### Étapes
1. **Tester** → `%x %x %x` → Format string confirmée
2. **Trouver position** → `AAAA%x.%x...` → Position 4
3. **Trouver adresse m** → `0x0804988c`
4. **Payload** : `[adresse_m][%60x][%4$n]`
5. **%n écrit 64** dans m → Shell ✅

### Notions clés
- Format string vulnerability
- `%x`, `%n`, `%4$n`
- Variables globales (`.bss`)
- Compteur de caractères

---

## 🎯 Level4 - Format String (grande valeur)

### Objectif de la faille
Écrire **16930116** dans `m` via format string.

### Étapes
1. **Position buffer** → Position 12 (stack frame supplémentaire)
2. **Adresse m** → `0x08049810`
3. **Conversion hex→dec** → `0x1025544` = 16930116
4. **Payload** : `[adresse_m][%16930112d][%12$n]`
5. **%n écrit 16930116** → Flag affiché ✅

### Notions clés
- Stack frame multiple
- Padding avec `%d`
- Conversion hex/décimal
- `system()` avec commande directe

---

## 🎯 Level5 - Format String + GOT Overwrite

### Objectif de la faille
Écraser **GOT[exit]** avec l'adresse de `o()` pour rediriger l'exécution.

### Étapes
1. **Adresse o()** → `0x080484a4` = 134513828
2. **GOT[exit]** → `objdump -R` → `0x08049838`
3. **Position buffer** → Position 4
4. **Payload** : `[GOT_exit][%134513824d][%4$n]`
5. **exit(1)** → GOT → o() → Shell ✅

### Notions clés
- GOT (Global Offset Table)
- GOT overwrite
- `objdump -R`
- `_exit()` vs `exit()`
- Format string + GOT

---

## 🎯 Level6 - Heap Overflow + Function Pointer

### Objectif de la faille
Écraser un **function pointer** sur le heap pour rediriger vers `n()`.

### Étapes
1. **malloc(64) + malloc(4)** → Adjacents sur heap
2. **Pattern/calcul** → Offset = 72 bytes (64 + 8 header)
3. **Adresse n()** → `0x08048454`
4. **Payload** : `"A"*72 + adresse_n()`
5. **(*func_ptr)()** → n() → Flag ✅

### Notions clés
- Heap overflow
- `strcpy()` vulnérable
- Function pointer
- Headers malloc (8 bytes)
- argv (vs stdin)

---

## 🎯 Level7 - Heap Overflow + Double Indirection + GOT

### Objectif de la faille
Utiliser **double indirection** pour écrire l'adresse de `m()` dans **GOT[puts]**.

### Étapes
1. **4 malloc()** → Layout heap avec structures
2. **Offset** → 20 bytes (vérifier avec GDB)
3. **argv[1]** : `"A"*20 + GOT_puts` → Redirige struct_b[1]
4. **argv[2]** : `adresse_m()` → Écrit dans GOT[puts]
5. **puts()** → m() → Flag ✅

### Notions clés
- Double indirection
- Write-what-where
- struct[1] = pointeur
- GOT overwrite via heap
- Ordre d'exécution (flag dans `c`)

---

## 🎯 Level8 - Use-After-Free + Out-of-Bounds Read

### Objectif de la faille
Faire en sorte que `auth + 32` contienne une valeur **non-nulle**.

### Étapes
1. **auth test** → Alloue 4 bytes à `0x0804a008`
2. **service XXXX...** (32+ chars) → Alloue après auth
3. **service[16+]** recouvre `auth + 32`
4. **login** → Lit `auth + 32` → Valeur non-nulle → Shell ✅

### Notions clés
- Variables globales
- Allocations séquentielles heap
- Out-of-bounds read
- Dangling pointer (avec `reset`)
- `strdup()`
- Programme interactif

---

## 🎯 Level9 - C++ vtable Hijacking + Shellcode

### Objectif de la faille
Écraser le **vtable pointer** de obj2 pour rediriger vers un **shellcode**.

### Étapes
1. **new N(5) + new N(6)** → obj1 et obj2 adjacents (108 bytes)
2. **Offset** → 104 bytes (vérifier avec GDB)
3. **Payload** : `[fausse_vtable][shellcode][padding][adresse_vtable]`
4. **setAnnotation()** → Overflow obj1 → Écrase vtable obj2
5. **operator+()** → vtable → shellcode → Shell ✅

### Notions clés
- C++ : classes, objets
- vtable (table virtuelle)
- vtable pointer (offset 0)
- Méthodes virtuelles
- Heap overflow (`memcpy`)
- vtable hijacking
- Shellcode injection
- Double indirection

---

## 📊 Vue d'ensemble des techniques

| Level | Technique principale | Zone mémoire | Cible |
|-------|---------------------|--------------|-------|
| 0 | Logic flaw | - | Condition |
| 1 | Buffer overflow | Stack | EIP (ret address) |
| 2 | Buffer overflow | Stack→Heap | EIP → Heap |
| 3 | Format string | Stack | Variable globale |
| 4 | Format string | Stack | Variable globale |
| 5 | Format string | Stack | GOT entry |
| 6 | Heap overflow | Heap | Function pointer |
| 7 | Heap overflow | Heap | GOT (via indirection) |
| 8 | Out-of-bounds read | Heap | auth + 32 |
| 9 | vtable hijacking | Heap | vtable pointer |

---

## 🎓 Compétences acquises

- ✅ Buffer overflow (stack + heap)
- ✅ Format string (lecture + écriture)
- ✅ Return-oriented (ret2func, ret2heap, ret2libc)
- ✅ GOT overwrite (direct + indirect)
- ✅ Function pointer hijacking
- ✅ vtable hijacking (C++)
- ✅ Shellcode injection
- ✅ Use-after-free
- ✅ Out-of-bounds access
- ✅ Tools : GDB, objdump, ltrace, pattern generator
