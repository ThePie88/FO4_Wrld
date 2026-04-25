# PIVOT: Strada A (custom D3D11) → Strada B (native Creation Engine)

**Data**: 2026-04-23
**Decisione**: Sospendere sviluppo Strada A. Pivot a Strada B.
**Codice Strada A**: preservato intatto, dormant (non invocato a init).
**Reversible**: sì, completamente (vedi "Come riattivare Strada A" in fondo).

## TL;DR

Dopo ~3-4 settimane di sviluppo Strada A abbiamo una pipeline custom D3D11 che:
- ✅ Renderizza MaleBody.nif al remote player pos, syncato via network
- ✅ Head placeholder sphere al collo
- ✅ Tracking pitch/yaw dal remote
- ❌ **Non risolve depth occlusion** (wallhack persiste)
- ❌ **Shake residuo** quando local player si muove

I due problemi restanti (depth + shake) richiedono accedere alla **vera scene depth + VP del gioco**, che abbiamo dimostrato essere **architetturalmente difficile** dal nostro render parallelo D3D11 — il gioco usa molti DSV (shadow, post-proc, scene, UI) tutti con stessa size, e la scene VP è TLS-indirect in NG 1.11.191.

**Strada B (native engine integration)** risolve entrambi GRATIS perché il Creation Engine renderizza il nostro body come ogni altro NPC nativo: shadow, lighting, depth, animations, tutto incluso.

**Tradeoff**: Strada B costa upfront (2-4 settimane RE + code) ma tutto il resto del progetto si semplifica enormemente.

## Stato Strada A al momento del pivot

### Cosa funziona (verified live)

- `MaleBody.fwn` load da disco, upload su GPU (1523 vertici, 58 bones, 1 submesh)
- Skinned vertex shader (col-major VP, identity bones → T-pose)
- Input layout matching vertex format 64 B (POS+NORM+UV+BIDX+BW)
- Head placeholder sphere procedurale (204 verts, lat/lon tessellation, peach skin color)
- Network remote snapshot → body segue Client B in world
- Pitch tracking da actor `rot[0]` → body-VP ruota up/down con camera locale
- Multi-mesh pattern: body + sphere in 2 draw call separati, stesso frame

### Cosa NON funziona / è deferred

- **Depth occlusion**: tutte le combinazioni `LESS_EQUAL`/`GREATER_EQUAL` × forward-Z/reverse-Z × near live/static testate, nessuna dà occlusione coerente. Il DSV che catturiamo è quasi certamente non la scene depth (shadow cascade o post-proc) ma filtrare il giusto DSV richiede draw-call-tracking ReShade-style che non abbiamo implementato.
- **Shake**: la nostra VP self-built (eye da `rot[0,2]` + perspective standard) non matcha byte-per-byte la VP del gioco. Small angular/translational errors = body shifts pixel amount when local moves = visible shake. Per fixare servirebbe `BSGraphics::State.viewProjMat` byte-exact, che è TLS-indirect non easily readable senza F4SE AddressLibrary.
- **Head mesh reale**: sphere placeholder invece di vera MaleHead.nif (quest'ultima è nei BA2 archives, richiederebbe extraction manuale via BAE o implementare BA2 parser).
- **Diffuse texture**: lambertian flat gray invece di skin texture vera.
- **Animations**: T-pose statico invece di animations HKX o fake walk.
- **Equipment/PA layering**: nessun armor/weapon overlay.

## Perché Strada A era difficile

### Fundamental: parallel rendering vs engine integration

Strada A è un renderer D3D11 **parallelo** al Creation Engine:
- Il gioco renderizza la scena con **la sua** VP, **i suoi** shader, **il suo** depth buffer
- Noi disegniamo nostri mesh con **la nostra** VP, **nostri** shader, bindando **il suo** depth buffer

Ogni comunicazione body↔gioco passa attraverso questo "ponte D3D11":
- Per synca depth: serve leggere la scene DSV (wrong DSV issues)
- Per no-shake: serve leggere la scene VP (TLS-indirect issues)
- Per shadow/lighting: impossibile (il gioco non sa che esistiamo)

### Specific failures incontrate

1. **DSV capture** prende il primo DSV con dimensioni backbuffer → finisce per essere shadow/post-proc
2. **VP capture via NiCamera+0x120** → il field non è aggiornato (scena usa diversa VP)
3. **VP capture via BSShaderAccumulator+0x17C** → struct layout variabile per accumulator (scene vs shadow vs cubemap), offset non stabile tra chiamate
4. **Depth convention ambigua** (forward-Z vs reverse-Z) → esausti tutti tentativi, comportamento resta random
5. **scene_render_hook @ sub_140C38F80** → hook installa e fires, ma matrice a NiCamera+0x120 a quel punto non è scene VP
6. **PlayerCamera+0x188 bufferedCameraPos** → contiene `foot + 120` semi-stabile, non bob reale
7. **Tutti questi tentativi documentati in** `docs/DEVIAZIONE_D3D11_to_CommonLibF4.md` e addendum al fondo di quel file

## Cosa si preserva di Strada A

### File che restano compilati ma dormant

Tutti i file in `src/render/` sono ancora nel CMakeLists e compilano. Il DLL li porta a bordo. Semplicemente `init_body_asset` non viene chiamato quindi niente si attiva.

| File | Stato | Riusabilità futura |
|---|---|---|
| `body_render.cpp` | Completo, funzionante | Base per future Strada A retrofit se utile |
| `head_placeholder.cpp` | Sphere funziona | Può servire per UI HUD gauge o other |
| `dsv_capture.cpp` | OMSetRenderTargets hook OK | Useful per altri DX11 intercepts |
| `scene_render_hook.cpp` | Hook installa, detour no-op | Useful per altre integrazioni engine |
| `vp_capture.cpp` | Install disabilitata | Reference for accumulator hook |
| `present_hook.cpp` | Present hook funziona | Essential se si riattiva Strada A |
| `triangle_render.cpp` | Debug triangle | Canary validation del D3D11 pipeline |

### Altri artefatti preservati

- `tools/PIEassetDecompiler/src/fwn_writer.cpp` — converte .nif → .fwn (compact mesh format). Potrebbe servire anche per Strada B se dobbiamo analizzare mesh.
- `assets/raw/Meshes/Actors/Character/CharacterAssets/MaleBody.nif` — mesh source
- `assets/compiled/MaleBody.fwn` — compiled mesh, used da body_render
- `src/assets/fwn_loader.cpp` — loader FWN format
- `src/offsets.h` — tutti gli RVA e offset scoperti (NI_CAMERA_*, PLAYER_CAMERA_*, SCENE_RENDER_RVA, etc.) sono molto utili ANCHE per Strada B

## Come RIATTIVARE Strada A (se mai serve)

### Minimal revive (body renders again, stesso state di oggi)

In `src/dll_main.cpp`, uncomment il blocco commentato:

```cpp
if (!fw::render::init_present_hook()) {
    FW_WRN("[render] Present hook init failed — B5 features disabled");
}
{
    const auto fwn_path = dir / "assets" / "compiled" / "MaleBody.fwn";
    if (!fs::exists(fwn_path)) {
        FW_WRN("[body] init: '%s' not found — body render disabled",
               fwn_path.string().c_str());
    } else if (!fw::render::init_body_asset(fwn_path)) {
        FW_ERR("[body] init_body_asset failed — body render disabled");
    }
}
```

Build + deploy. Stato torna a: body visibile + shake + wallhack. Esattamente come al momento del pivot.

### Full fix tentatives (per risolvere depth + shake)

Se si vuole rifinire Strada A fino a production:

**Piano ReShade-style depth fix (4-6 ore)**:
1. Hook `ID3D11DeviceContext::DrawIndexed`, `Draw`, `DrawIndexedInstanced`, `DrawInstanced` (vtable slots 12, 13, 20, 21)
2. Track quale DSV è bound (da OMSetRenderTargets) al momento di ogni draw call
3. Count draw calls per DSV per frame
4. Main scene DSV = quello con MAX count (scene: migliaia, shadow: centinaia)
5. Hook `ID3D11DeviceContext::ClearDepthStencilView` (vtable slot ~53)
6. Quando game clears main DSV → prima `CopyResource` in nostra backup texture D32_FLOAT non-MSAA
7. Creare SRV sulla backup texture
8. Body pixel shader: `SampleLevel(backup_depth, uv, 0)` poi `if (body_ndc_z > backup_z) discard`
9. Questo evita anche il problema MSAA (se scene DSV è multisampled, `CopyResource` o `ResolveSubresource` in single-sample backup)

**Piano BSGraphics VP capture (per shake)**:
- Scaricare F4SE AddressLibrary per 1.11.191 (file .bin con ID→RVA mapping)
- Parseggiare per trovare `BSGraphics::State::GetSingleton()` (REL::ID(600795))
- Accedere `ViewData.viewProjMat` @ `State+0x230` + `posAdjust` @ `State+0x370`
- Usare quella VP byte-exact nel nostro body render
- Risolve shake completamente

Riferimenti utili:
- ReShade draw-call tracking: https://github.com/crosire/reshade/pull/38
- Depth buffer docs: https://guides.martysmods.com/reshade/depth/
- CommonLibF4 ViewData layout: `CommonLibF4/include/RE/Bethesda/BSGraphics.h`

## Strada B: dove si va

Approccio: creare un valid `NiNode` / `BSTriShape` engine-side, attachare nostro mesh + skeleton, inserire nel scene graph. Il Creation Engine renderizza il nostro body come un NPC nativo.

**Vantaggi gratis dal pivot**:
- ✅ Depth occlusion nativa (engine uses its own DSV correctly)
- ✅ Shadow nativo (directional + point lights)
- ✅ Lighting BSLightingShader nativo (diffuse, specular, SSAO)
- ✅ VP shake impossibile (stesso VP del gioco)
- ✅ Animations nativi (link a BSAnimationGraphManager + skeleton.nif)
- ✅ Mesh customization completa (invece di puppet NPC statico)

**Costi upfront**:
- ~2-4 settimane di RE + code
- Rischio crashi da scene graph integrity, race conditions, refcounting

**Milestone proposti**:
1. **M1 De-risk** (~3-5 giorni): creare "debug cube" come `BSTriShape`, attaccarlo al scene root, verificare che il gioco lo renderizzi senza crash. Se funziona → feasibility confirmed.
2. **M2 MaleBody native** (~1 settimana): convert FWN → `BSVertexData` format, link skeleton, body renderizza staticamente a posizione fissa
3. **M3 Dynamic positioning** (~3 giorni): update `NiAVObject::local.translate` per frame da remote snapshot
4. **M4 Animations** (~1-2 settimane): link a `BSAnimationGraphManager` o driving bones manuali
5. **M5 Head + Equipment** (~1-2 settimane): multi-mesh + armor/weapon layering

## Lesson learned

- **"Stand on giants' shoulders"**: quando hai l'engine intero a disposizione, non c'è motivo di ricostruire il render pipeline parallelo. Usa ciò che già esiste.
- **Parallel rendering is a dead-end**: per ogni feature volevi aggiungere (depth, shadow, lighting, anim) avresti dovuto ri-implementarla da zero. Sbagliato architetturalmente.
- **RE first, implement second**: molte iterazioni sprecate su depth/shake erano guessing su convenzioni engine. Il web search ReShade ha dato risposta in 30 min che 3 giorni di IDA non avevano dato con certezza.

## Sentiment

Strada A era un tour de force tecnico. Tutta la pipeline D3D11 manuale (kiero Present hook, custom shaders, skinned mesh renderer, head placeholder, DSV capture, scene_render_hook, vp_capture) è stata scritta da zero e funziona al 80%. Il 20% mancante (depth + shake) è architetturalmente bloccato dal parallel rendering approach. Non è colpa del codice, è colpa del paradigma.

Il codice non si butta — può servire da reference, da base se si vuole estendere engine con overlay custom (es. custom UI HUD, debug visualizer, screenshot mode), o come base per un Strada A-retrofit se mai Strada B fallisce. Ma per la **missione "ghost player body credibile multiplayer"**, Strada B è la strada.
