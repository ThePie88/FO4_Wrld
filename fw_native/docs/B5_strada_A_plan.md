# B5 "Strada A" — D3D11 custom render ghost player

**Ambizione**: equipment-replicating ghost indistinguibile dal player vero, superando i limiti noti di Skyrim Together v1/v2.

**Contesto**: scelto 2026-04-21 dopo esame di L2 (actor hijack + equip sync) e L3 (D3D11 custom). User ha scelto L3 perché voleva full control + scalabilità a gameplay custom futuro.

**Stima onesta**: 4-5 mesi serali. Non è un MVP — è un block di produzione.

## Limiti noti di Skyrim Together (target da superare)

| Limite ST | Nostra soluzione pianificata |
|---|---|
| Zombie walk (animation sync imperfetto) | Bone-level transform sync, non solo state machine |
| Equipment desync (enchant, tempered) | Full form-data sync includendo ExtraData |
| IK approssimativo (foot planting, look-at) | FABRIK proper con full joint constraints |
| Flicker residuo (actor-based hijack) | No actor system — ghost è skeleton+mesh custom |
| Power Armor assente (Skyrim non ha PA, ma analoghi transform) | PA frame-swap logic replicato 1:1 |

## Struttura 5 fasi

### Fase α — Asset pipeline (3-4 settimane)

**Goal**: saper caricare qualunque asset FO4 in memoria, via un formato binario custom.

| # | Task | Effort |
|---|---|---|
| α.1 | Offline asset extraction (BAE / nifly CLI) — **user-side** | 1-2 serate |
| α.2 | NIF parser C++ (vertices, indices, bone weights, submeshes) | 2 settimane |
| α.3 | BGSM/BGEM material parser (shader params Bethesda) | 1 settimana |
| α.4 | DDS texture loader → `ID3D11Texture2D` | 3-4 serate |
| α.5 | Custom binary "asset bundle" format (pre-converted NIF+BGSM+DDS) | 3-4 serate |

**Output**: da un `.nif` Bethesda → struct in memoria con mesh + materials + texture refs.
**Decisione checkpoint**: se NIF parser fallisce dopo 2 settimane, pivot al tool esterno `nifly` come dipendenza embedded.

### Fase β — Base rendering (2-3 settimane)

**Goal**: ghost T-pose visibile in world-space, ancorato al player remoto.

| # | Task | Effort |
|---|---|---|
| β.1 | Load body mesh (malebodytpose.nif) into VB/IB | 3-4 serate |
| β.2 | Skeleton loader (bone hierarchy + default pose) | 3-4 serate |
| β.3 | Matrix palette CB + skinning VS (4-weight) | 3-4 serate |
| β.4 | Shader PBR Bethesda-equivalent (HLSL) — base diffuse+normal+specular | 1 settimana |
| β.5 | Camera matrices (RE: view+proj from game, no our approximation) | 3-4 serate |
| β.6 | Ghost ancorato a remote player pos+rot | 2 serate |

**Output**: 2 client lanciati → ognuno vede l'altro come ghost umanoide T-pose vestito grigio in world-space, mesh e skinning puliti.
**Decisione checkpoint**: dopo β.5 (camera matrices), validiamo che la view matches perfettamente — se è off, ghost appare warped.

### Fase γ — Animation system (4-6 settimane) — **IL KILLER**

**Goal**: ghost muove bone correttamente replicando azioni del player remoto.

| # | Task | Effort |
|---|---|---|
| γ.1 | HKX parser (Havok format reverse engineering) | **2-4 settimane** ⚠️ |
| γ.2 | Animation data loader: carico walk/run/idle/aim/reload dai HKX estratti | 3-4 serate |
| γ.3 | Animation state machine custom (clip selection + frame time) | 1 settimana |
| γ.4 | Bone transform computation per frame (FK) + blend between states | 1 settimana |
| γ.5 | Network sync: capture state machine del player remoto → serialize → apply | 1 settimana |

**Risk bucket**: HKX è closed format Havok. Community tools (hctConvert, hkparser) sono parziali/rotti per versioni recenti. Se γ.1 fallisce:
- **Fallback 1**: precompute offline (estrarre bone transforms come flat frame-by-frame data)
- **Fallback 2**: reverse engineering full runtime animation state + bone transforms via memory read (più invasivo ma evita HKX)

**Output**: ghost cammina, corre, si gira, mira, ricarica — animazioni vanilla visibili.

### Fase δ — Equipment & Power Armor (3-4 settimane)

**Goal**: ghost indossa armor/weapons/PA replicando 1:1 il remote player.

| # | Task | Effort |
|---|---|---|
| δ.1 | Equipment slot system (head/chest/arms/legs/weapon/PA) | 3-4 serate |
| δ.2 | Multi-NIF rendering (body + armor pieces + weapon) | 1 settimana |
| δ.3 | Material swapping per slot (ogni piece ha suo BGSM) | 3-4 serate |
| δ.4 | Weapon pose sync (arma attached a WeaponR bone + animation state) | 3-4 serate |
| δ.5 | **Power Armor special case**: PA NON è armor equip in FO4 — è body-swap a frame PA + moduli | **1-2 settimane** ⚠️ |
| δ.6 | Equipment change network sync (protocol ext) + dynamic reload ghost | 1 settimana |

**Risk bucket**: Power Armor in FO4 ha logica speciale engine. Quando entri in PA, il PlayerCharacter è "nascosto" e sostituito da PA frame (ACHR separato). Replicare questo cross-client richiede RE della PA transform logic.

**Output**: ghost con armor/weapon/PA esattamente uguale al remote player.

### Fase ε — Sync & Polish (3-4 settimane)

| # | Task | Effort |
|---|---|---|
| ε.1 | FABRIK IK (foot planting, look-at, weapon hold) | 1 settimana |
| ε.2 | Lighting integration (hook nel game's forward/deferred pass) | 1-2 settimane |
| ε.3 | Ragdoll / death physics | 1 settimana |
| ε.4 | Occlusion culling (ghost dietro muri non disegnato) | 3-4 serate |
| ε.5 | Performance profiling + optimization | 1 settimana |

**Output**: ghost production-ready, visually clean, frame-rate-safe.

## Totale

**15-21 settimane serali = 4-5 mesi** per completezza.
**MVP ghost visibile** (fine Fase β): **5-7 settimane**.
**MVP animato** (fine Fase γ): **9-13 settimane**.

## Ordine di attacco operativo

1. **Ora**: asset extraction offline (user fa tool-side) — 1-2 serate
2. **Settimana 1-2**: NIF parser v1 (solo body T-pose)
3. **Settimana 3**: static mesh rendering (body T-pose, no skinning)
4. **Settimana 4-5**: skeleton + skinning → body ancorato al player remoto
5. **Settimana 6-7**: camera matrices RE + material system base
6. **Settimana 8+**: animation system (IL KILLER, entriamo nel rischio HKX)

## Decisioni aperte che andranno prese durante il path

1. **NIF parser**: scriviamo da zero in C++ o portiamo nifly?
2. **HKX parser**: scriviamo, portiamo, o fallback runtime memory-read?
3. **Material system**: HLSL shader equivalente (alto effort) o approssimazione minima (low effort)?
4. **Formato asset binario**: serialization custom o reutilizzo glTF?
5. **Texture pipeline**: runtime DDS load o pre-convert to raw DX11 resource?

Queste le risolviamo al punto giusto del plan, non adesso.

## Per non buttare il lavoro Step 1+2 già fatto

Il Present hook + triangle renderer restano utili:
- Test harness per verificare che il nostro render pipeline è vivo
- Debug overlay (bone visualization, bounding boxes, skeleton in wireframe)
- HUD/UI overlay per la quest UI hijack (Opzione 1 user choice)
- Performance overlay (frame time, bone count, draw call count)

Il `triangle_render.cpp` evolverà a `mesh_render.cpp` (Fase β) e poi `skinned_mesh_render.cpp` (Fase γ).

---

## Next step operativo

User side: estrazione asset offline. Serve solo 1 sera, poi tutto il resto è code io. Vedi documento `fw_native/docs/B5_asset_extraction_howto.md` quando lo scrivo.
