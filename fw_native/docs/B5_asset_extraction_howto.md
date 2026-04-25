# B5 Fase α.1 — Asset extraction offline

**Scopo**: estrarre da Fallout 4 NG un set minimale di asset (mesh + skeleton + materials + textures) da usare come input per il nostro NIF parser C++. Questa è una operazione **una tantum** tool-side — non serve codice nostro.

**Output atteso**: folder `fw_native/assets/raw/` popolato con file `.nif`, `.bgsm`, `.dds`.

---

## Asset target

Per MVP Fase β (body T-pose rendering) servono solo 3-4 file:

1. `meshes/actors/character/characterassets/skeleton.nif` — hierarchia bone del player
2. `meshes/actors/character/characterassets/malebody.nif` — body mesh (male vanilla, T-pose)
3. Un texture body set (diffuse + normal + specular) — es. `textures/actors/character/basehumanmale/basemalebody_d.dds`
4. Il corrispondente material `.bgsm` — es. `materials/actors/character/basehumanmale/basemalebody.bgsm`

Per Fase δ (equipment) aggiungeremo dopo armor + weapon, step separato.

---

## Tool da installare

Hai due opzioni equivalenti per l'extraction da `.BA2` archive:

### Opzione A — **BAE (Bethesda Archive Extractor)** (GUI, più semplice)

1. Download da Nexus: <https://www.nexusmods.com/fallout4/mods/78>
2. Unzip ovunque, es. `C:\tools\BAE\`
3. Lancia `BAE.exe`

### Opzione B — **B.A.E. command line** o **bsab.exe** (CLI, scriptabile)

- `bsab.exe -e <archive> <pattern> <out>` — una riga per estrazione batch
- Disponibile su GitHub, es. `matortheeternal/bsa-browser` fork con CLI

Consiglio: **Opzione A** (GUI) per questa prima sessione, Opzione B per pipeline automatizzata futura.

---

## Step-by-step (Opzione A — BAE)

### Step 1 — Aprire gli archive giusti

Gli asset player stanno in 3 archive principali (in `C:\Program Files (x86)\Steam\steamapps\common\Fallout 4\Data\`):

- `Fallout4 - Meshes.ba2` (geometria: .nif)
- `Fallout4 - Materials.ba2` (materiali: .bgsm, .bgem)
- `Fallout4 - Textures1.ba2`, `Textures2.ba2`, etc. (texture: .dds)

In BAE: **File → Open** → seleziona prima `Fallout4 - Meshes.ba2`.

### Step 2 — Estrarre skeleton + body mesh

Nel tree nav di BAE, naviga a:
```
meshes/actors/character/characterassets/
```

Seleziona:
- `skeleton.nif` (~100KB) — hierarchia bone, fondamentale
- `malebody.nif` (~500KB-1MB) — mesh body vanilla maschile

Click destro → **Extract** → destinazione `C:\Users\filip\Desktop\FalloutWorld\fw_native\assets\raw\meshes\`

Preserva la directory tree nell'estrazione (l'opzione di default).

### Step 3 — Estrarre material

Chiudi `Meshes.ba2`, apri `Fallout4 - Materials.ba2`.

Naviga a:
```
materials/actors/character/basehumanmale/
```

Seleziona `basemalebody.bgsm` (+ eventuale `basemaleHead.bgsm` se ti va). Extract a:
```
C:\Users\filip\Desktop\FalloutWorld\fw_native\assets\raw\materials\
```

### Step 4 — Estrarre texture

Chiudi il precedente, apri `Fallout4 - Textures1.ba2`. Naviga a:
```
textures/actors/character/basehumanmale/
```

Seleziona:
- `basemalebody_d.dds` (diffuse, colore)
- `basemalebody_n.dds` (normal map)
- `basemalebody_s.dds` (specular) se presente

Se non li trovi qui, prova `Fallout4 - Textures2.ba2` / `Textures3.ba2` / `Textures4.ba2` — le texture player sono splittate tra più archive.

Extract a:
```
C:\Users\filip\Desktop\FalloutWorld\fw_native\assets\raw\textures\
```

### Step 5 — Verifica struttura finale

```
C:\Users\filip\Desktop\FalloutWorld\fw_native\assets\raw\
├── meshes\
│   └── actors\
│       └── character\
│           └── characterassets\
│               ├── skeleton.nif
│               └── malebody.nif
├── materials\
│   └── actors\
│       └── character\
│           └── basehumanmale\
│               └── basemalebody.bgsm
└── textures\
    └── actors\
        └── character\
            └── basehumanmale\
                ├── basemalebody_d.dds
                ├── basemalebody_n.dds
                └── basemalebody_s.dds
```

Totale **~5-10 MB** di asset. Check: tutti i file hanno dimensione >0 e apri una .dds in un viewer (Paint.NET con plugin, o Windows Explorer thumbnail) per conferma visiva che è una texture umana e non rumore binario.

---

## Checkpoint

Quando finito:
1. Fai `ls -la fw_native/assets/raw/meshes/actors/character/characterassets/` e verifica che `skeleton.nif` e `malebody.nif` sono estratti
2. Dimmi "fatto" qui
3. Io parto con Fase α.2 (NIF parser C++) usando `skeleton.nif` come primo test case

---

## Note di scope

- **Niente armor/weapon qui**: li estraiamo in Fase δ, non serve ora
- **Niente animation (.hkx)**: li estraiamo quando entriamo in Fase γ — sono in `meshes/animationdata/` e `meshes/actors/character/animations/`
- **Niente female body**: per MVP solo male vanilla. Female + race altri arrivano dopo nell'iterazione equipment
- **Power Armor**: estrazione dedicata in Fase δ.5 (PA frame + moduli sono in `meshes/armor/powerarmor/`)

Tutto il resto resta in `.BA2` fino a quando non ci serve per una fase specifica.
