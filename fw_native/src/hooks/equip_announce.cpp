// =============================================================================
// equip_announce — implementation. The why, the measurement it stands on and
// the history of the scaffold that lived here are in equip_announce.h.
// =============================================================================

#include "equip_announce.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>

#include "../log.h"
#include "../engine/engine_calls.h"    // get_local_player
#include "../native/scene_inject.h"    // ghost_scene_settled
#include "../net/client.h"             // enqueue_equip_op
#include "../net/protocol.h"           // EquipModRecord, EquipOpKind
#include "equip_hook.h"                // read_worn_item_for_wire

namespace fw::hooks {

namespace {

// The inventory layout, as pa_pipeline_trace.cpp documents it above its dump:
//   REFR+0xF8  BGSInventoryList*
//     +0x58    entries, stride 0x10:
//                +0x00 TESBoundObject*  (+0x1A form type, +0x14 form id)
//                +0x08 head of the stack chain
//     +0x68    entry count
//   stack:
//     +0x10    next stack
//     +0x20    count
//     +0x24    flags — the engine's own "equipped" filter is (flags & 7) != 0
constexpr std::size_t kInvListOff     = 0xF8;
constexpr std::size_t kEntriesOff     = 0x58;
constexpr std::size_t kCountOff       = 0x68;
constexpr std::size_t kEntryStride    = 0x10;
constexpr std::size_t kEntryStackOff  = 0x08;
constexpr std::size_t kFormIdOff      = 0x14;
constexpr std::size_t kFormTypeOff    = 0x1A;
constexpr std::size_t kStackNextOff   = 0x10;
constexpr std::size_t kStackFlagsOff  = 0x24;
constexpr std::uint8_t kEquippedMask  = 0x07;
// Measured 2026-09-23 on the local player: the Vault 111 suit and the
// Pip-Boy read 0x1D, the pistol and the baton 0x2B, stimpaks 0x30, ammo 0x2C.
constexpr std::uint8_t kFormTypeApparel = 0x1D;

// POD-only SEH readers. Every read of engine memory goes through one of
// these, so a list torn under us costs a skipped entry, not the process.
void* inv_ptr(void* base, std::size_t off) noexcept {
    if (!base) return nullptr;
    __try { return *reinterpret_cast<void**>(static_cast<char*>(base) + off); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}
std::uint32_t inv_u32(void* base, std::size_t off) noexcept {
    if (!base) return 0;
    __try { return *reinterpret_cast<std::uint32_t*>(static_cast<char*>(base) + off); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}
std::uint8_t inv_u8(void* base, std::size_t off) noexcept {
    if (!base) return 0;
    __try { return *reinterpret_cast<std::uint8_t*>(static_cast<char*>(base) + off); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// Raised by a session start, lowered by the tick that serves it.
std::atomic<bool> g_pending{false};

std::uint64_t wall_ms() {
    using namespace std::chrono;
    return static_cast<std::uint64_t>(duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()).count());
}

// L5 stage 3d — the respawn difference: the apparel worn at the death, and
// the flag the respawn raises for the tick. g_death_mx guards the list.
constexpr std::size_t kMaxWorn = 64;
std::mutex    g_death_mx;
std::uint32_t g_death_worn[kMaxWorn] = {};
std::size_t   g_death_worn_n = 0;
bool          g_death_noted = false;
std::atomic<bool> g_respawn_pending{false};

struct WornItem { std::uint32_t fid; void* obj; };

// Every apparel form of the local player with an equipped stack, one per
// form. -1 when the inventory cannot be read; `not_apparel` counts the
// equipped forms of another type (the weapon), `walked` the entries.
int collect_worn_apparel(void* player, WornItem* out, std::size_t cap,
                         unsigned* not_apparel, std::uint32_t* walked) {
    *not_apparel = 0;
    *walked = 0;
    void* list = inv_ptr(player, kInvListOff);
    if (!list) return -1;
    const std::uint32_t count = inv_u32(list, kCountOff);
    void* entries = inv_ptr(list, kEntriesOff);
    // Only a defence against a count read wrong: a player inventory can
    // legitimately exceed the 64 the PA dump caps at.
    if (!entries || count > 4096) return -1;
    *walked = count;
    std::size_t n = 0;
    for (std::uint32_t i = 0; i < count && n < cap; ++i) {
        void* obj   = inv_ptr(entries, i * kEntryStride);
        void* stack = inv_ptr(entries, i * kEntryStride + kEntryStackOff);
        if (!obj || !stack) continue;
        bool equipped = false;
        int si = 0;
        for (void* s = stack; s && si < 16; s = inv_ptr(s, kStackNextOff), ++si) {
            if (inv_u8(s, kStackFlagsOff) & kEquippedMask) { equipped = true; break; }
        }
        if (!equipped) continue;
        const std::uint32_t fid  = inv_u32(obj, kFormIdOff);
        const std::uint8_t  type = inv_u8(obj, kFormTypeOff);
        if (fid == 0) continue;
        if (type != kFormTypeApparel) { ++*not_apparel; continue; }
        out[n++] = WornItem{fid, obj};
    }
    return static_cast<int>(n);
}

void send_equip(void* player, const WornItem& w, std::uint64_t now) {
    fw::net::EquipModRecord mods[fw::net::MAX_EQUIP_MODS] = {};
    std::uint16_t prio = 0;
    const std::uint8_t n = read_worn_item_for_wire(
        player, w.obj, w.fid, mods,
        static_cast<std::uint8_t>(fw::net::MAX_EQUIP_MODS), &prio);
    fw::net::client().enqueue_equip_op(
        w.fid, static_cast<std::uint8_t>(fw::net::EquipOpKind::EQUIP),
        /*slot_form_id=*/0, /*count=*/1, now, prio,
        n ? mods : nullptr, n, /*nif_descs=*/nullptr, /*nif_count=*/0);
}

// The respawn difference (see the header). `equips` false when a full
// session-start announce runs in the same tick and sends the EQUIPs itself.
void announce_respawn_diff(void* player, bool equips) {
    std::uint32_t died[kMaxWorn] = {};
    std::size_t nd = 0;
    {
        std::lock_guard<std::mutex> lk(g_death_mx);
        nd = g_death_worn_n;
        for (std::size_t i = 0; i < nd; ++i) died[i] = g_death_worn[i];
        g_death_worn_n = 0;
        g_death_noted = false;
    }
    WornItem now_items[kMaxWorn] = {};
    unsigned not_apparel = 0;
    std::uint32_t walked = 0;
    const int nn = collect_worn_apparel(player, now_items, kMaxWorn, &not_apparel, &walked);
    if (nn < 0) {
        FW_WRN("[equip-announce] respawn: the inventory cannot be read; the ghost of this "
               "player keeps the outfit of the death");
        return;
    }
    const std::uint64_t now = wall_ms();
    unsigned off = 0, on = 0, kept = 0;
    for (std::size_t i = 0; i < nd; ++i) {
        bool still = false;
        for (int j = 0; j < nn; ++j) {
            if (now_items[j].fid == died[i]) { still = true; break; }
        }
        if (still) continue;
        fw::net::client().enqueue_equip_op(
            died[i], static_cast<std::uint8_t>(fw::net::EquipOpKind::UNEQUIP),
            /*slot_form_id=*/0, /*count=*/1, now, /*priority=*/0,
            nullptr, 0, /*nif_descs=*/nullptr, /*nif_count=*/0);
        ++off;
        FW_DBG("[equip-announce]   form=0x%08X worn at the death, not now: UNEQUIP", died[i]);
    }
    for (int j = 0; j < nn; ++j) {
        bool before = false;
        for (std::size_t i = 0; i < nd; ++i) {
            if (died[i] == now_items[j].fid) { before = true; break; }
        }
        if (before) { ++kept; continue; }
        if (!equips) continue;
        send_equip(player, now_items[j], now);
        ++on;
        FW_DBG("[equip-announce]   form=0x%08X worn now, not at the death: EQUIP",
               now_items[j].fid);
    }
    FW_LOG("[equip-announce] respawn: %u item(s) worn at the death and not now -> UNEQUIP, "
           "%u worn now and not at the death -> EQUIP%s, %u unchanged",
           off, on, equips ? "" : " (sent by the session announce)", kept);
}

} // namespace

void equip_announce_on_session_start() {
    g_pending.store(true, std::memory_order_release);
    FW_DBG("[equip-announce] session started: the worn outfit will be "
           "announced once the scene has settled");
}

void equip_announce_note_death() {
    void* player = fw::engine::get_local_player();
    WornItem items[kMaxWorn] = {};
    unsigned not_apparel = 0;
    std::uint32_t walked = 0;
    const int n = player ? collect_worn_apparel(player, items, kMaxWorn, &not_apparel, &walked)
                         : -1;
    std::lock_guard<std::mutex> lk(g_death_mx);
    g_death_worn_n = 0;
    g_death_noted = n >= 0;
    for (int i = 0; i < n; ++i) g_death_worn[g_death_worn_n++] = items[i].fid;
    if (n < 0) {
        FW_WRN("[equip-announce] death: the inventory cannot be read; the respawn will "
               "announce the whole outfit instead of the difference");
    } else {
        FW_LOG("[equip-announce] death: %d worn apparel item(s) noted for the respawn", n);
    }
}

void equip_announce_after_respawn() {
    bool noted;
    {
        std::lock_guard<std::mutex> lk(g_death_mx);
        noted = g_death_noted;
    }
    if (noted) {
        g_respawn_pending.store(true, std::memory_order_release);
        FW_DBG("[equip-announce] respawn: the outfit difference goes out once the scene has "
               "settled");
    } else {
        g_pending.store(true, std::memory_order_release);
        FW_LOG("[equip-announce] respawn with no note of the death: the whole outfit is "
               "announced once the scene has settled");
    }
}

void equip_announce_tick() {
    const bool session = g_pending.load(std::memory_order_acquire);
    const bool respawn = g_respawn_pending.load(std::memory_order_acquire);
    if (!session && !respawn) return;
    // The stability gate already requires the player in the world, a cell,
    // no load in flight, and resets if the player's 3D is rebuilt under us —
    // so this never reads the inventory halfway through a power armor enter.
    if (!fw::native::ghost_scene_settled()) return;
    void* player = fw::engine::get_local_player();
    if (!player) return;

    if (respawn) {
        g_respawn_pending.store(false, std::memory_order_release);
        announce_respawn_diff(player, /*equips=*/!session);
        if (!session) return;
    }

    // Lowered BEFORE the walk, not after: a WELCOME that lands while this
    // runs raises it again, and the next tick announces again — which is the
    // right answer for a session that restarted under us.
    g_pending.store(false, std::memory_order_release);

    void* list = inv_ptr(player, kInvListOff);
    if (!list) {
        FW_WRN("[equip-announce] the local player has no inventory list — "
               "nothing announced, the ghost of this player replays naked");
        return;
    }
    const std::uint32_t count = inv_u32(list, kCountOff);
    void* entries = inv_ptr(list, kEntriesOff);
    // Only a defence against a count read wrong: a player inventory can
    // legitimately exceed the 64 the PA dump caps at.
    if (!entries || count > 4096) {
        FW_WRN("[equip-announce] inventory entries missing or count "
               "implausible (%u) — nothing announced", count);
        return;
    }

    const std::uint64_t now = wall_ms();
    unsigned announced = 0, with_mods = 0, equipped_not_apparel = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        void* obj   = inv_ptr(entries, i * kEntryStride);
        void* stack = inv_ptr(entries, i * kEntryStride + kEntryStackOff);
        if (!obj || !stack) continue;

        // Is any stack of this entry equipped? One EQUIP per form, however
        // many stacks it has.
        bool equipped = false;
        int si = 0;
        for (void* s = stack; s && si < 16; s = inv_ptr(s, kStackNextOff), ++si) {
            if (inv_u8(s, kStackFlagsOff) & kEquippedMask) { equipped = true; break; }
        }
        if (!equipped) continue;

        const std::uint32_t fid  = inv_u32(obj, kFormIdOff);
        const std::uint8_t  type = inv_u8(obj, kFormTypeOff);
        if (fid == 0) continue;
        if (type != kFormTypeApparel) {
            // The equipped weapon lands here. It reaches the ghost on its
            // own path, with mesh descriptors; see the header.
            ++equipped_not_apparel;
            FW_DBG("[equip-announce]   form=0x%08X type=0x%02X equipped, not "
                   "apparel — left to its own path", fid, type);
            continue;
        }

        fw::net::EquipModRecord mods[fw::net::MAX_EQUIP_MODS] = {};
        std::uint16_t prio = 0;
        const std::uint8_t n = read_worn_item_for_wire(
            player, obj, fid, mods,
            static_cast<std::uint8_t>(fw::net::MAX_EQUIP_MODS), &prio);

        fw::net::client().enqueue_equip_op(
            fid,
            static_cast<std::uint8_t>(fw::net::EquipOpKind::EQUIP),
            /*slot_form_id=*/0,          // what the live hook sends for apparel
            /*count=*/1,
            now,
            prio,
            n ? mods : nullptr,
            n,
            /*nif_descs=*/nullptr,
            /*nif_count=*/0);

        ++announced;
        if (n) ++with_mods;
        FW_DBG("[equip-announce]   form=0x%08X worn — %u OMOD(s), "
               "priority %u", fid, static_cast<unsigned>(n),
               static_cast<unsigned>(prio));
    }

    FW_LOG("[equip-announce] announced %u worn apparel item(s), %u of them "
           "with OMODs; %u equipped non-apparel item(s) left to their own "
           "path (%u inventory entries walked)",
           announced, with_mods, equipped_not_apparel, count);
}

} // namespace fw::hooks
