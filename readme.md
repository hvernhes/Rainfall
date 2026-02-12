# Utilisation de Ghidra pour la décompilation

Ce guide explique comment installer et utiliser Ghidra pour décompiler un binaire ELF.

---

## Installation de Ghidra

### Prérequis : Java 21+
```bash
# Vérifier la version de Java
java -version

# Si nécessaire, installer Java 21
sudo apt update
sudo apt install openjdk-21-jdk
```

### Télécharger et installer Ghidra
```bash
cd ~/downloads

# Télécharger Ghidra (version 11.2.1)
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2.1_build/ghidra_11.2.1_PUBLIC_20241105.zip

# Décompresser
unzip ghidra_11.2.1_PUBLIC_20241105.zip
cd ghidra_11.2.1_PUBLIC

# Lancer Ghidra
./ghidraRun
```

---

## Décompilation d'un binaire

### 1. Récupérer le binaire depuis la VM
```bash
# Copier le binaire via SCP
scp -P 4242 level0@192.168.1.45:~/level0 ~/downloads/
```

### 2. Créer un projet Ghidra

1. `File` → `New Project`
2. Sélectionner **Non-Shared Project**
3. Nom du projet : `Rainfall`
4. Choisir un emplacement
5. Cliquer `Finish`

### 3. Importer le binaire

1. `File` → `Import File`
2. Naviguer vers le binaire (ex: `~/downloads/level0`)
3. Sélectionner le fichier
4. Ghidra détecte automatiquement :
   - **Format** : Executable and Linking Format (ELF)
   - **Language** : x86:LE:32:default (Intel 80386, little endian)
5. Cliquer `OK`

### 4. Analyser le binaire

1. Double-cliquer sur le binaire dans la liste du projet
2. Pop-up : **"level0 has not been analyzed. Would you like to analyze it now?"**
3. Cliquer `Yes`
4. Garder les options d'analyse par défaut
5. Cliquer `Analyze`
6. Attendre la fin de l'analyse (10-20 secondes)

### 5. Naviguer vers la fonction main

**Interface Ghidra (3 panneaux) :**
```
┌──────────────┬─────────────────────┬──────────────────┐
│ Symbol Tree  │ Listing (ASM)       │ Decompile (C)    │
│              │                     │                  │
│ - Functions  │ 08048ec0 PUSH EBP   │ int main(...) {  │
│   - main     │ 08048ec1 MOV ...    │   int input;     │
│   - atoi     │ ...                 │   ...            │
└──────────────┴─────────────────────┴──────────────────┘
```

1. **Panneau gauche** : Symbol Tree → Dérouler **Functions**
2. Chercher et double-cliquer sur `main`
3. Le code décompilé apparaît dans le **panneau de droite**

---

## Améliorer la lisibilité du code décompilé

### Éditer la signature de la fonction

1. Dans le **panneau Listing** (centre), clic droit sur `main`
2. Sélectionner **`Edit Function Signature`**
3. Modifier la signature :
   - De : `undefined4 main(undefined4 param_1, int param_2)`
   - Vers : `int main(int argc, char **argv)`
4. Cliquer `OK`

### Renommer les variables

**Dans le panneau Decompile (droite) :**

1. Clic droit sur une variable (ex: `iVar1`)
2. Sélectionner **`Rename Variable`**
3. Entrer un nom explicite (ex: `input`)
4. Cliquer `OK`

### Changer le type d'une variable

**Exemple : Transformer une variable en tableau**

1. Clic droit sur la variable
2. Sélectionner **`Retype Variable`**
3. Modifier le type (ex: `char *` → `char *[2]`)
4. Cliquer `OK`

### Convertir une valeur hexadécimale en décimal

1. Dans le panneau Decompile, clic droit sur la valeur (ex: `0x1a7`)
2. **`Convert`** → **`Decimal`**
3. La valeur devient `423`

---

## Exporter le code décompilé

1. Dans le **panneau Decompile**, sélectionner le code
2. **Clic droit** → **`Copy to Clipboard`** (ou `Ctrl+C`)
3. Coller dans votre fichier `source`
4. Nettoyer et annoter le code manuellement

---

## Résoudre les problèmes courants

### Erreur : "Project is locked"

Le fichier de verrouillage n'a pas été supprimé correctement.

**Solution :**
```bash
# Tuer tous les processus Ghidra
pkill -9 -f ghidra

# Supprimer les fichiers de verrouillage
cd ~/ghidra-projects/Rainfall
rm -f .lock *.lock
rm -rf .project.lock
```

### Ghidra ne trouve pas Java
```bash
# Trouver le chemin Java
readlink -f $(which java)
# Exemple de résultat : /usr/lib/jvm/java-21-openjdk-amd64/bin/java

# Définir JAVA_HOME
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64

# Relancer Ghidra
./ghidraRun
```

---

## Notes importantes

- Ghidra laisse parfois les constantes en **hexadécimal** (ex: `0x1a7`) pour préserver la forme originale
- Les noms de variables générés (`local_1c`, `iVar1`) doivent être renommés pour la lisibilité
- Le code décompilé est un **point de départ** : il faut le nettoyer et l'annoter manuellement
- Ghidra peut générer des types système avec des préfixes (`__gid_t`, `__uid_t`) qui peuvent être simplifiés