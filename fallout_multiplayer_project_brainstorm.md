# Fallout 4 Multiplayer Project — Brainstorming & Design Document

*Riassunto completo della sessione di brainstorming — aprile 2026*

---

## 1. Contesto e premesse

### 1.1 Perché è fallito Fallout Together (stato dell'arte)

Due mod multiplayer principali per Fallout 4 si sono fermate entrambe, per motivi diversi:

- **Fallout Together** (team Skyrim Together): messo in pausa indefinita. Nel 2022 il dev cosideci/Robbe ha dichiarato mancanza di tempo e manodopera. Passato a open source ma fermo. Richiederebbe conoscenze intermedio-avanzate di C++, reverse engineering, e centinaia di ore per risolvere i problemi del codice di FO4 che causano crash. Il team aveva anche provato con Starfield Together (portato ~70% del codice) ma ha abbandonato.

- **Fallout 4 Multiplayer Mod (F4MP)** di Hynsung Go: in sviluppo 2019-2020, release prevista fine 2020, ma lo sviluppatore principale si è ritirato. Altri hanno provato a continuare senza successo.

**Il problema di fondo è tecnico, non solo umano**: il Creation Engine non è stato progettato per il multiplayer. Sincronizzare AI, VATS, quest scriptate, physics e save state tra client richiede essenzialmente di riscrivere pezzi del motore via reverse engineering. VATS in particolare è un incubo perché rallenta il tempo per un solo giocatore.

### 1.2 Il ruolo dell'AI tooling moderno

Gli ultimi anni hanno cambiato radicalmente il reverse engineering:

- Ghidra + plugin LLM, IDA + Copilot/Sidekick, RevEng.AI, LLM4Decompile
- Nomi di variabili sensati in secondi invece di giorni
- Riconoscimento di pattern noti in codice decompilato
- Identificazione automatica di funzioni di engine riutilizzate

**Dove l'AI accelera**: la fase di *comprensione* del codice (trovare dove si aggiorna la posizione NPC, serializzazione save state, internals di Papyrus VM). Settimane → giorni.

**Dove l'AI accelera meno**: architettura netcode (cosa sincronizzare/no), gestione VATS in multiplayer, quest scriptate pensate per single-player, save divergenti, race condition distribuite stateful. Qui serve ancora ingegneria umana.

### 1.3 Engine di Fallout 76

Non è Creation Engine 2 (quello debutta con Starfield nel 2023), è un Creation Engine 1 pesantemente modificato:

- Netcode bolted-on sopra un engine single-player di 20 anni (causa dei problemi al lancio)
- Papyrus lato client rimosso per molte quest (gestite server-side o rimpiazzate con event system)
- Streaming celle rivisto per multi-player nella stessa worldspace
- Rendering aggiornato (volumetric lighting, draw distance, weather) — tecnologia poi confluita in CE2
- Hook modding castrati lato client per anti-cheat

### 1.4 Considerazioni su copiare da Fallout 76

**Consenso raggiunto**: non copiare codice (illegale e inutile), ma usare FO76 come **case study architetturale**:

- Le tecnologie multiplayer in sé non sono proprietarie (standard da 20 anni di game networking)
- Pattern di quest sync, persistenza, actor replication, inventory auth sono da manuale
- Utile sapere *cosa* Bethesda ha dovuto toccare nel CE per farlo funzionare online, senza disassemblare 30k righe
- Approccio corretto: giocare, osservare, leggere datamine community, incrociare con F4SE knowledge

Parallelo con AI coding tools: Zencoder/Replit/OpenHands non hanno "copiato" Claude Code, hanno reimplementato pattern noti. Stesso rapporto tra Postgres/MySQL, React/Vue, Docker/Podman. Ispirazione architetturale, non copyright infringement.

---

## 2. Evoluzione del concept

### 2.1 Opzioni iniziali considerate

Tre modelli di multiplayer diversi, valutati e scartati:

1. **Co-op + Campagna** (Divinity/BG3 style): 2-4 amici nella main quest. Tecnicamente facile (host authoritative), ma rompe la narrativa single-Sole-Survivor.
2. **MMO con campagna istanziata** (ESO/FO76 style): troppo complesso, 5+ anni di team.
3. **Survival MMO PVP** (Rust/DayZ style): ignora la campagna, emergent gameplay. Ridimensionato ma interessante.

### 2.2 Pivot verso Elden Ring-Fallout

Il punto di svolta è stata l'idea di **"Elden Ring-ificare" Fallout 4**:

- Taglia il problema della narrativa single-player (no Sole Survivor, no Shaun, niente main quest Bethesda)
- Boss open-world sono sync-pattern semplice (actor + HP + attacchi, non quest scriptate)
- Base building già esistente in FO4
- Combat deliberato Souls-like funziona anche con netcode mediocre (a differenza di twitch shooter)
- Scope negoziabile: v0.1 può usare Commonwealth vanilla + pochi boss

### 2.3 Concept finale: Survival persistent universe

Dopo ulteriori iterazioni, il concept si è stabilizzato su:

> **Survival MMO hardcore per piccoli gruppi stabili (max 10 player), con progressione lenta, rischio reale permanente, emergent narrative, Nemesis System-lite, base Fallout 4 con estetica Souls-like PVE.**

Target player: gruppi di 4-10 amici che vogliono investire mesi in un server persistente con possibilità di perdere tutto. Nicchia sotto-servita (Tarkov senza Fallout, DayZ senza base building, Rust troppo PVP, Conan non Fallout).

---

## 3. Design decisions finali

### 3.1 Architettura server

- **Server authoritative** (no P2P con host)
- **Server meshing a zone, griglia 8x8** sulla mappa
- **Shard congelato** se non ha player (DB persiste stato)
- Più vicino a New World / WoW che a Star Citizen vero (più fattibile)
- **10 player max per server**
- Con griglia 8x8 e 10 player: nella maggior parte dei casi 1-3 shard attivi, gli altri congelati. Carico gestibile.

### 3.2 Modello sociale

- **I 10 player = una sola entità narrativa**
- NPC che parla con X equivale a parlare con Y
- Zero sync di quest state per singolo player
- Zero race condition su quest completion
- Reputazione e quest sono di gruppo, non individuali

### 3.3 Raid e persistence

- **Sempre raidabile** (no offline protection) — rischio reale è parte del tema
- **Raid notturni schedulati dal server** contro basi di player con fazioni nemiche
- Filtra il pubblico verso hardcore, ma coerente con design

### 3.4 Sistema di progressione geografica

- **Level-gating implicito via geografia**: più scendi a sud più sale il livello
- Nessun obbligo esplicito, ma morte certa se impreparato
- Pattern "peek-and-die tourism" come Valheim Plains — emergent narrative
- Ispira racconti del tipo "sono morto a lv40 con un personaggio lv5 per vedere il drop"

### 3.5 Gestione worldstate e ripopolamento

**Sistema elegante in-fiction per evitare esaurimento del server**:

- Se i player sterminano una regione, NPC non respawnano
- Player possono buildarci sopra (regione "conquistata")
- Se la regione rimane vuota troppo a lungo, **si auto-ripopola con giustificazione narrativa**:
  - Tempesta radioattiva
  - Nuke inesplosa che esplode
  - Espansione di una fazione alleata (problema se diventa invadente — carneficina possibile)
  - Espansione di una fazione nemica
- Livello zona aumenta dopo ripopolamento
- Transizioni triggered: `DEPOPULATED → [30 giorni] → RE_CONTAMINATED → [7 giorni] → FACTION_EXPANSION / MONSTER_NEST`
- Cron job per shard, totalmente fattibile

### 3.6 Sistema fazioni

- **Quest procedurali semplici**: porta X tappi, uccidi Y, cucina Z
- Template JSON + random picker, non quest scriptate
- Reputazione di gruppo (non individuale)
- Effetti concreti:
  - **Reputazione alta**: sconti mercanti, reward unici, possibili NPC follower
  - **Reputazione bassa**: +50% prezzi, ban dalla base fazione, raid notturni alla base player
- **Grind intenzionalmente lento**: Marco può tryhardare da solo senza rompere l'esperienza per il gruppo

### 3.7 Sistema Nemesis (versione light)

Nota legale: il sistema completo è brevettato da WB (US10807006, scade ~2035). Per mod non commerciale sei probabilmente fuori radar, ma attenzione se monetizzi.

**Versione fattibile "Nemesis-lite"**:

- Ogni boss fazione ha stato `(name, traits[], memory[], rank)`
- Alla morte, successore promosso con traits influenzati da *come* è morto il predecessore:
  - Ucciso con esplosivi → successore ha tratto "armor heavy"
  - Ucciso nel sonno → successore "paranoid, extra guards"
- Successore riconosce player con barks condizionali pre-scritti
- 40% dell'esperienza Shadow of War con 10% del lavoro
- Abbastanza diverso per essere difendibile come clean-room

### 3.8 Sistema di durabilità e morte

**Scelta originale: soft-cap decrescente**

- A morte: equipaggiamento perde **30% della durabilità MASSIMA** (non totale)
- L'arma non si rompe mai ma degrada performance nel tempo
- Effetti graduali per essere "sentiti" dal player:
  - 70%: inceppamenti occasionali
  - 50%: recoil aumentato
  - 30%: spread visibile
  - 10%: rischio esplosione in mano

**Gotcha identificato**: death spiral. 5-6 morti portano l'arma a ~14% max. Richiede sink permanente per materiali di riparazione. Possibile soluzione:
- **Field Repair**: materiali comuni, ripristina fino a 80% del max
- **Workshop Repair**: componenti rari (nucleo atomico, ecc.), ripristina 100%

### 3.9 Crafting gated per materiali

- **No level gating del crafting**, solo material gating
- Esempio: armatura atomica a lv5 è inutile senza nucleo raro
- Crea tensione: il player vede il drop, capisce il valore, deve decidere se rischiare
- Spinge all'esplorazione di zone high-level anche a livelli bassi
- Materiali rari spawnano solo a sud (zone lv alto)

### 3.10 Gestione morte e loot

- Loot al cadavere con **grave persistente timer lungo (~96 ore)**
- Permette organizzazione "spedizione di recupero" con compagni di gruppo più forti
- Crea gameplay organico ("aiutatemi, devo recuperare")

### 3.11 VATS

- **Senza rallentamento tempo** (come in FO76)
- Ripensato come *abilità attiva real-time*: action points per auto-aim preciso ma player resta vulnerabile
- Non più "pausa tattica" di FO4, è un sistema nuovo che usa l'UI di VATS
- Compatibile con feeling Souls-like

### 3.12 Sistema survival mantenuto da Fallout

- Cibo, acqua, cure, radiazione, siringhe di tutti i tipi
- Pipboy e skills rimangono
- Crafting e base building
- Post-apocalittico, loot in giro
- **Deve rimanere un Fallout, non diventare altro gioco con asset Fallout**

---

## 4. Roadmap tecnica

### 4.1 Stack di sistemi da costruire

1. Reverse engineering Creation Engine (hooking runtime, non solo file format)
2. Networking stack custom con server authoritative
3. Sistema persistenza a shard con database
4. Porting/adaptation FO4 per headless server mode (incerto)
5. Quest system rifatto
6. Faction system + reputazione
7. Base building persistente multi-player
8. Nemesis lite system
9. Balancing, testing, iterazione
10. Art/writing per fazioni, lore, boss

### 4.2 Milestone zero: spawn senza intro

**Primo step concordato**: bypassare tutto il pre-war intro, cutscene Vault 111, character creator. Droppare direttamente nel Commonwealth con personaggio di default in 10 secondi.

**Perché è il passo giusto**:
- Deliverable visibile veloce, morale alta
- Forza a capire il save system (utile dopo per multiplayer)
- Crea test harness riusabile per tutto lo sviluppo
- Espone al quest system in modalità lettura (serve prima di toccarlo)

**Approcci possibili**:

- **Console command scripting** (hacky, veloce): AutoHotkey o plugin F4SE che esegue `coc SanctuaryExt` + setstage al main menu
- **Save template pre-cucinato** (intermedio): save manuale fuori dal Vault, plugin F4SE che bypassa main menu e lo carica automaticamente
- **New Game flow rifatto via plugin** (pulito, riusabile): mod che rimpiazza MQ101 con versione che MoveTo player a cella custom e setta flag. Base di partenza per il "nuovo gioco" del multiplayer finale

**Decisione aperta**: spawn location dell'hub persistente. Sanctuary è ovvio ma decisione da prendere subito per non rifare lo step dopo.

### 4.3 Approcci tecnici per "ghost player"

Quando arriverà il momento di rappresentare un secondo player nel mondo:

- **A — Actor injection**: spawna NPC vanilla e ne sovrascrive posizione/animation. Gratis animazioni, collision, LOD. Problemi: AI package da sopprimere, animation blending gommoso, inventory sync complesso.
- **B — Custom render layer**: bypass actor system, mesh skinnata via render loop hook. Controllo totale, latenza minima. Richiede reimplementazione di animation, collision, IK.
- **C — Papyrus-based**: F4SE + plugin Papyrus. Facile ma Papyrus tick 60ms+, ghost "ubriaco". Non serio, ma molti prototipi partono qui.

Skyrim Together è partito da A e ha migrato verso B. Probabile scelta: direttamente B o ibrido, con server authoritative da subito (non P2P a due processi locali) per non buttare codice dopo.

---

## 5. Questioni aperte da decidere

1. Cosa succede al loot in zone irraggiungibili per player low-level dopo morte?
2. Crafting tier segue geografia o perk-lock?
3. Il gruppo da 10 può dividersi su server diversi o è tutto-o-niente?
4. Fazioni ostili: parlabili a prezzo raddoppiato o sparo-a-vista?
5. Voice chat proximity o no? Cambia tono (DayZ vs Valheim).
6. Location hub persistente: Sanctuary, Prydwen precipitata, o altro?
7. Prima fazione da implementare (definisce tono del gioco).
8. Death drop: tutto all'inventario al cadavere, solo non-equipaggiato, o solo caps?
9. Rete di field repair vs workshop repair: soglie e costi precisi.
10. Criteri di promozione Nemesis-lite: quali tratti, quanti, come visualizzarli al player.

---

## 6. Scope realistico

### 6.1 MVP onesto

- 1 server
- 16 player max (poi 10 come scelto)
- Commonwealth vanilla
- 1 fazione con reputazione
- 5 quest template procedurali
- Base building funzionante
- 2 boss regionali
- NPC con persistenza di morte
- No raid offline inizialmente
- Drop-on-death parziale
- PVE only all'inizio

**Stima**: 12-18 mesi di lavoro serale serio con AI tooling e skill forti.

### 6.2 Stima full vision

3-4 anni di lavoro serale serrato per singolo dev skilled, oppure 2 anni per team di 3-5.

### 6.3 Posizionamento di mercato

Nessuna vera competizione nella nicchia target. Anche al 40% della vision completata, il gioco occupa uno spazio vuoto (survival MMO hardcore small-group Fallout). Downside ridotto.

---

## 7. Consigli pratici

### 7.1 Gestione del progetto

- **Devlog dal giorno 1** (pubblico o privato): screenshot, commit diff, "oggi ho ottenuto X". Carburante vero è poter guardare indietro al mese 6 e vedere il progresso. Singolo trucco che separa i side project che finiscono da quelli che muoiono.
- **Separare visione da MVP**: la visione può essere grande, l'MVP deve essere piccolo. Pattern pericoloso del brainstorming: ogni feature sembra "solo un piccolo extra" ma aggiunge 6 mesi.
- **Milestone piccoli e misurabili** per le prime settimane invece di obiettivi grandi. Evita il "mi sento indietro" quando raggiungi un buon risultato ma non quello che ti eri promesso.

### 7.2 Grind e retention

- Marco tryharder = Quartermaster del gruppo (risorse, reputazione, logistica)
- Content principale (boss, dungeon, raid) richiede gruppo attivo
- Gating secondario: "boss fazione richiede N player online con livello X"
- Milestone frequenti e visibili, numeri nascosti dietro
- "Brotherhood ti saluta invece di ignorarti" > "Reputation 2340/50000"

---

## 8. Decisioni coerenti vs tensioni da risolvere

### 8.1 Decisioni che si rinforzano

- 10 player = 1 entità ↔ quest di gruppo ↔ reputazione di gruppo = design sociale coerente
- Level gating geografico ↔ material gating crafting ↔ peek-and-die tourism = loop di esplorazione coerente
- Soft-cap durabilità ↔ material repair tiers ↔ need per materiali rari = economy sink coerente
- Raid sempre possibili ↔ rischio reale ↔ filtro hardcore = tone coerente
- Shard 8x8 ↔ ripopolamento in-fiction ↔ fazioni dinamiche = worldstate coerente

### 8.2 Tensioni ancora aperte

- "Souls-like" vs "Fallout survival" → risolto tenendo entrambi ma gestendo il gap narrativo con lore ambientale + quest procedurali fazione
- "Server authoritative" vs "scope fattibile singolo dev" → risolto scegliendo "sharded persistent" (tipo New World) invece di "server meshing" (tipo Star Citizen)
- "Grind lento" vs "retention" → da monitorare con milestone visibili frequenti
- "Persistent universe" vs "esaurimento server" → risolto con ripopolamento in-fiction

---

*Fine documento.*
