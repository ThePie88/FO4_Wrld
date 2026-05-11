// 22_dump_placed_actors.js — B6.5w3 prep
//
// Captures form_id + position of every PLACED actor whose AI tick fires
// during a short window. Designed to be run live while standing in a cell
// with the target NPCs (e.g. Drumlin Diner, Lexington-Corvega entrance,
// Saugus Ironworks main floor).
//
// How it works:
//   - Hooks Actor::Update_PerFrame at RVA 0xC636A0 (RE'd in
//     re/B6.5_npc_pipeline_AGENT_A.md — single funnel for all 3
//     ProcessLists tier walkers + 5 forced-tick sites).
//   - Each fire, reads form_id at Actor+0x14 (TESForm.formID, verified
//     stable in 10b_verify_formid_offset.js) and pos at Actor+0xD0
//     (verified for any Actor in 10_find_npc.js).
//   - Filters out 0xFF__ runtime refs (leveled-list spawns) — those have
//     per-process formIDs and CANNOT be replicated across clients in
//     MVP. Only 0x00__ placed refs (authored in .esm) survive the
//     filter; those are stable across processes/saves.
//   - Dedupes by form_id; logs once per unique placed actor.
//   - Auto-detaches after WINDOW_MS so the game keeps running.
//
// Usage:
//   1. Load a save where the target NPCs are ALIVE and PRESENT.
//   2. Travel to their cell, stop within visible range.
//   3. Run:  frida -p <pid> -l frida/22_dump_placed_actors.js
//   4. Wait until "[done] captured N placed actor(s)" prints.
//   5. Pick 3 actors from the output → paste here, we update
//      net/server/waypoints/drumlin_diner.json (form_id + pos).
//
// What's NOT captured (intentionally):
//   - base_id (TESNPC). Quickest follow-up: console `prid 0xXXX`,
//     then `getbaseobject`. Optional for MVP — receiver uses form_id
//     as primary lookup key; base_id is just a validation hint.
//   - cell_id. Console: `prid 0xXXX`, then look at parent cell on map.
//     Optional for MVP — interest management is B6.7+.
//   - rotation. Read at Actor+0xC0 if needed; current waypoint flow
//     starts NPCs facing their first waypoint, so initial yaw doesn't
//     matter for the demo.

const FORMID_OFF      = 0x14;
const POS_OFF         = 0xD0;
const PER_ACTOR_TICK  = 0xC636A0;   // Actor::Update_PerFrame (B6.5w0 dossier)
const RUNTIME_MASK    = 0xFF000000; // form_id ≥ this means leveled-list spawn
const WINDOW_MS       = 3000;

const fo4 = Process.findModuleByName('Fallout4.exe');
console.log('[+] Fallout4.exe base=' + fo4.base);

const tickAddr = fo4.base.add(PER_ACTOR_TICK);
console.log('[+] Hooking Actor::Update_PerFrame at ' + tickAddr +
            ' (RVA 0x' + PER_ACTOR_TICK.toString(16) + ')');

const seen = new Map();   // form_id -> { x, y, z }

const hook = Interceptor.attach(tickAddr, {
    onEnter: function (args) {
        try {
            const actor = args[0];
            const formId = actor.add(FORMID_OFF).readU32();
            // Drop runtime (0xFF__) refs — leveled spawns can't be replicated.
            if ((formId & RUNTIME_MASK) === RUNTIME_MASK) return;
            // Drop the player (typically formID 0x00000007 / 0x00000014 in FO4).
            if (formId === 0x14 || formId === 0x07) return;
            if (seen.has(formId)) return;

            const x = actor.add(POS_OFF).readFloat();
            const y = actor.add(POS_OFF + 4).readFloat();
            const z = actor.add(POS_OFF + 8).readFloat();
            seen.set(formId, { x: x, y: y, z: z });

            console.log(
                '  placed actor formid=0x' +
                formId.toString(16).padStart(8, '0') +
                '  pos=(' + x.toFixed(1) + ', ' + y.toFixed(1) + ', ' + z.toFixed(1) + ')'
            );
        } catch (e) {
            // Defensive — bad reads happen during cell streaming, just skip.
        }
    },
});

console.log('[+] Capturing for ' + (WINDOW_MS / 1000) + 's...');
setTimeout(function () {
    hook.detach();
    console.log('\n[done] captured ' + seen.size + ' unique placed actor(s)');
    if (seen.size === 0) {
        console.log('[!] No placed actors ticked during window. Possible causes:');
        console.log('    - Standing too far from any NPC (tier-Low actors don\'t tick PerFrame)');
        console.log('    - All nearby actors are leveled spawns (0xFF__) — try Drumlin Diner / Lexington');
        console.log('    - Game was paused (open menu / loading screen)');
    } else {
        console.log('[+] Paste this list into the chat to update drumlin_diner.json');
        console.log('--- BEGIN PASTE ---');
        seen.forEach(function (pos, fid) {
            console.log('formid=0x' + fid.toString(16).padStart(8, '0') +
                        '  pos=(' + pos.x.toFixed(1) + ', ' + pos.y.toFixed(1) + ', ' + pos.z.toFixed(1) + ')');
        });
        console.log('--- END PASTE ---');
    }
    send({ type: 'done', count: seen.size });
}, WINDOW_MS);
