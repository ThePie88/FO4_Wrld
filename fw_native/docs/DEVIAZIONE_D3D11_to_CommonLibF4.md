# DEVIAZIONE dal D3D11 path originale (2026-04-22)

## Contesto e decisione

Il piano B5 originale (`planoB_custom_renderer.md`) prevedeva di costruire
tutta la pipeline di custom render da zero: hook D3D11, mesh loader FWN,
skinning, bone palette, shader HLSL, view-proj reconstruction dal player
pose. Tutto fatto in casa.

Arrivati a **β.6 — depth/view-proj integration** ci siamo bloccati sul
capire il formato della matrice cached a `NiCamera+288` dentro
FirstPersonState (PlayerCamera singleton @ RVA 0x30DBD58).

### Cosa abbiamo provato (e perché non ha convergito)

1. **Interpretazione row-major + pre-subtract eye** — body visibile ma
   sballato, diagonale quando si ruota la camera (screenshot 2026-04-22 16:20).
2. **Interpretazione row-major + world coords** — body clippato al top
   dello schermo (NDC.y=3.15).
3. **Interpretazione column-major + world coords** — body clippato dal
   near plane (NDC.z=-0.008).
4. **IDA static analysis** — identificate RVA chiave, dumpate
   ctor/vtable/clone method, ma la semantica precisa del float[16] a
   `+288` resta ambigua (row_major? column_major? view? view-proj?
   world-view-proj? camera-relative? world-absolute?).
5. **MCC (MainCullingCamera) probe** — singleton esiste (RVA 0x32D25D0)
   ma `+288` è unpopulated (zeri + NaN). Dead end.

Ogni tentativo richiede un build-deploy-test cycle. Abbiamo speso ~8h e
non convergiamo. Il problema root: **stiamo tirando a indovinare la
semantica di uno struct interno di Bethesda senza documentazione**.

## Cosa cambia

**Non stiamo più inventando offset.** Usiamo come **reference** la
libreria community `CommonLibF4` (fork maintained per next-gen 1.11.191),
che ha tutti gli struct di Creation Engine **già RE'd, tipizzati,
validati da 5+ anni di modding**. MIT license → zero rischio legale.

### Cosa NON facciamo

- **Non integriamo tutta CommonLibF4 come dependency** (sarebbe mesi di
  lavoro di refactoring + binding a F4SE ecosystem).
- **Non pivot a plugin F4SE** — restiamo proxy `dxgi.dll` + MinHook.

### Cosa facciamo

Usiamo CommonLibF4 come **dizionario**:
1. Apriamo `CommonLibF4/include/RE/N/NiCamera.h` (o equivalente).
2. Leggiamo la definizione dello struct — ci dice ESATTAMENTE quale
   campo a `+288` è (e.g., `worldToCam`, `viewProj`, `frustum`, etc.).
3. Importiamo solo gli **offset** dentro il nostro `src/offsets.h`.
4. Il codice nostro (`engine_calls.cpp`, `body_render.cpp`) legge quei
   field con la semantica corretta documentata.

Risultato atteso: la matrice che leggiamo ha un **nome** e una
**convenzione** (row/column major, world-relative / camera-relative,
view-only / view-proj) documentata nell'header. Niente più guessing.

## Impatto sul piano B5

- **β.6 depth+wobble fix**: si sblocca non appena sappiamo cos'è la
  matrice a +288. Stima 1-2 giorni dopo aver importato gli offset.
- **β.5 diffuse**: invariato.
- **γ HKX animation**: potenzialmente accelerato se CommonLibF4 ha
  struct per BSAnimationGraphManager.
- **δ equipment/PA**: idem per ArmorAddon / BGSBodyPartData.

## Cosa succede se CommonLibF4 non ha NG coverage

Non tutti i fork sono completi per 1.11.191 next-gen. Fallback:
1. **IDA targeted**: decompilare singole funzioni (SetupTechnique,
   UpdateView, etc.) e dedurre offset dall'output.
2. **angr** (symbolic execution Python): se IDA dà troppo rumore,
   usiamo angr per risolvere constraint su specifici write-sites.
3. **triton** (dynamic analysis): per tracciare flow di dati live in
   runtime se static analysis non basta.

Strategia: tutti e tre in parallelo come agenti se single-tool fallisce.

## Filosofia di fondo

**"Stand on giants' shoulders"** — 5 anni di modding community hanno
già RE'd gli struct. Usiamo il loro lavoro invece di rifare. Se qualcosa
manca lo aggiungiamo noi con IDA/angr/triton e contribuiamo upstream se
appropriato.

Il custom D3D11 rendering rimane l'obiettivo architetturale. Cambia
solo come arriviamo a capire il Creation Engine: da "guess + iterate" a
"riferimento tipizzato + verify".

## Addendum (2026-04-23): VP capture tentativi esauriti, shake deferred

Dopo ~30 iterazioni sul problema dello shake del body (tremolio quando
il local player cammina / muove camera), abbiamo esaurito 4 approcci
distinti per catturare la vera scene ViewProj:

1. **Self-built VP** (lookAt + perspective da player pose): funzionante
   per sync + orientation + pitch, ma shake inevitabile perché la nostra
   VP non combacia byte-per-byte con quella del gioco (bob, smoothing,
   interpolation mancano).

2. **NiCamera+0x120** (worldToCam): la matrice c'è e ha scale di f/a,
   f, EYE_HEIGHT — sembrava un VP. Ma in live test produceva body
   storto/sballato con ogni interpretazione di math conventions
   (row-major vs col-major, row-vec vs col-vec, Y-flip o no, xy-swap
   o no). Probabilmente il field è aggiornato per pass diversi (shadow,
   cubemap, UI) tra scene render e Present → stiamo leggendo l'ultimo
   che passa, non quello della scena.

3. **sub_140C38F80 scene walker trailing hook + NiCamera+0x120**:
   stessa matrice, stesso risultato. Hook preservato per uso futuro
   (depth capture) ma non usabile per VP.

4. **sub_14221E6A0 BSShaderAccumulator consumer hook**: agente RE
   indicava matrix a accumulator+0x17C. Live dump: quella offset è
   garbage (solo zeri con 1 sparso). A +0x1A0 a volte identity, a
   volte una 4x4 reale MA è camera-to-world (translation = eye pos),
   NON world-to-clip. L'offset varia per accumulator (shadow vs scene
   vs reflection). Struct layout non è costante tra accumulators
   diversi. Impossible isolare "lo scene accumulator" senza deeper
   RE sulla vtable BSShaderAccumulator.

**Decisione pragmatica**: accept shake come known limit. Body è comunque
**visibile, sync con Client B, rotazione e pitch corretti**. Lo shake è
cosmetico e non blocca la pipeline multiplayer.

Avanziamo a β.5 (diffuse texture), head/hands extraction, γ (animazioni
HKX) che sono fasi con valore aggiunto e attori diversi. Torneremo allo
shake più tardi con:
- Più context di rendering acquisito
- Possibile RE di BSShaderAccumulator vtable per filtrare scene vs altri
- Possibile nuovo approach: hook D3D11 draw calls e lettura CB GPU-side
- O pivot a BSDynamicTriShape integration (body come scene object nativo)

File di codice preservati in `src/render/`:
- `scene_render_hook.cpp` — hook su sub_140C38F80, detour no-op
- `vp_capture.cpp` — hook su sub_14221E6A0, install-call disabilitata
  ma compilato. Future: scan accumulators per trovare vero scene VP.
