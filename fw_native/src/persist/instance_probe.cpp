#include "instance_probe.h"

#include <windows.h>
#include <intrin.h>

#include <atomic>
#include <cmath>
#include <cstdio>

#include "../config.h"
#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../ref_identity.h"
#include "inventory_capture.h"
#include "lifecycle.h"

namespace fw::persist::probe {

namespace {

bool           g_enabled = false;
std::uintptr_t g_base    = 0;

// sub_14052EB10(u16 oldUid, u32 oldOwner, u16 newUid, u32 newOwner,
// u32 base). Every parameter is declared 64-bit (the project's rule:
// registers and stack slots are not zero-extended) and the meaningful
// width is cut out of it when read.
using UidChangeFn = std::int64_t (__fastcall*)(std::uint64_t old_uid, std::uint64_t old_owner,
                                               std::uint64_t new_uid, std::uint64_t new_owner,
                                               std::uint64_t base);
UidChangeFn g_orig_uid_change = nullptr;

std::atomic<std::uint64_t> g_uid_events{0};
std::atomic<std::uint64_t> g_load_gen{~0ull};
std::atomic<std::uint64_t> g_load_lines{0};
// A load can move every uid of a save's inventory: the first ones are
// listed (they say whether the loader reassigns at all), the rest counted.
constexpr std::uint64_t kLoadLinesMax = 64;

std::int64_t __fastcall detour_uid_change(std::uint64_t old_uid, std::uint64_t old_owner,
                                          std::uint64_t new_uid, std::uint64_t new_owner,
                                          std::uint64_t base) {
    const auto ret = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
    const std::int64_t rc = g_orig_uid_change(old_uid, old_owner, new_uid, new_owner, base);
    const std::uint64_t n = g_uid_events.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool loading = fw::persist::load_in_flight();
    if (loading) {
        const std::uint64_t gen = fw::persist::loads_requested();
        if (g_load_gen.exchange(gen, std::memory_order_relaxed) != gen) {
            g_load_lines.store(0, std::memory_order_relaxed);
        }
        const std::uint64_t k = g_load_lines.fetch_add(1, std::memory_order_relaxed) + 1;
        if (k > kLoadLinesMax) {
            if (k == kLoadLinesMax + 1) {
                FW_LOG("[uid] more than %llu uid moves during this load: the rest are "
                       "counted (total so far in the event counter), not listed",
                       static_cast<unsigned long long>(kLoadLinesMax));
            }
            return rc;
        }
    }
    FW_LOG("[uid] #%llu base=0x%08X uid %u@%08X -> %u@%08X from +0x%llX tid %lu%s",
           static_cast<unsigned long long>(n), static_cast<std::uint32_t>(base),
           static_cast<unsigned>(static_cast<std::uint16_t>(old_uid)),
           static_cast<std::uint32_t>(old_owner),
           static_cast<unsigned>(static_cast<std::uint16_t>(new_uid)),
           static_cast<std::uint32_t>(new_owner),
           static_cast<unsigned long long>(ret - g_base),
           static_cast<unsigned long>(GetCurrentThreadId()), loading ? " (load)" : "");
    return rc;
}

const char* type_name(std::uint8_t t) noexcept {
    switch (t) {
    case 0x1D: return "ARMO"; case 0x2B: return "WEAP"; case 0x2A: return "AMMO";
    case 0x1E: return "BOOK"; case 0x2C: return "MISC"; case 0x20: return "ALCH";
    case 0x2D: return "NPC_"; case 0x32: return "NOTE"; case 0x1F: return "KEYM";
    default: return "?";
    }
}

} // namespace

void configure(const fw::config::Settings& cfg) {
    g_enabled = cfg.instance_probe;
    FW_LOG("[probe] instance probe %s", g_enabled
           ? "ON (stage 4a): uid moves, stacks around every transfer, apply, rollback and "
             "realignment, the capture's records at info"
           : "off (instance_probe=false)");
}

bool enabled() noexcept { return g_enabled; }

int install(std::uintptr_t module_base) {
    g_base = module_base;
    if (!g_enabled || !module_base) return 0;
    void* target = reinterpret_cast<void*>(module_base + offsets::UNIQUE_ID_CHANGE_EVENT_RVA);
    const bool ok = fw::hooks::install(target, reinterpret_cast<void*>(&detour_uid_change),
                                       reinterpret_cast<void**>(&g_orig_uid_change));
    if (ok) {
        FW_LOG("[probe] uid-change detour installed at 0x%llX (sub_14052EB10)",
               static_cast<unsigned long long>(module_base + offsets::UNIQUE_ID_CHANGE_EVENT_RVA));
    } else {
        FW_ERR("[probe] uid-change detour FAILED at 0x%llX: no [uid] lines this session, "
               "the stack dumps still run",
               static_cast<unsigned long long>(module_base + offsets::UNIQUE_ID_CHANGE_EVENT_RVA));
    }
    return ok ? 1 : 0;
}

void log_stack(const char* tag, const fw::persist::inventory::StackRecord& r, int chain,
               bool transient, std::uint32_t base_flags) {
    using namespace fw::persist::inventory;
    char mods[MAX_OIE_RECORDS * 20 + 4];
    mods[0] = '\0';
    std::size_t p = 0;
    for (std::uint32_t k = 0; k < r.oie_count && k < MAX_OIE_RECORDS; ++k) {
        const int w = std::snprintf(mods + p, sizeof(mods) - p, "%s%X:%u:%u:%u", k ? "," : "",
                                    r.oie[k].mod_form_id, unsigned(r.oie[k].attach_index),
                                    unsigned(r.oie[k].rank), unsigned(r.oie[k].flag));
        if (w <= 0 || static_cast<std::size_t>(w) >= sizeof(mods) - p) break;
        p += static_cast<std::size_t>(w);
    }
    char chain_s[12];
    if (chain < 0) std::snprintf(chain_s, sizeof(chain_s), "-");
    else std::snprintf(chain_s, sizeof(chain_s), "%d", chain);
    char hp[20];
    if (std::isnan(r.health)) std::snprintf(hp, sizeof(hp), "none");
    else std::snprintf(hp, sizeof(hp), "%.3f", r.health);
    const bool has_uid = (r.extra_mask & MASK_UNIQUE_ID) != 0;
    const bool has_oie = (r.extra_mask & MASK_OIE) != 0;
    FW_LOG("[probe] %s 0x%08X %s x%d #%s fl=0x%04X%s%s uid=%s%u@%08X oie=%s tmpl=0x%04X "
           "mods=%u[%s]%s hp=%s name='%s' bf=0x%08X%s fp=%016llX/%016llX%s%s%s",
           tag, r.base_id, type_name(r.form_type), r.count, chain_s, unsigned(r.flags),
           (r.flags & offsets::INV_STACK_FLAG_EQUIPPED) ? " E" : "", transient ? " T" : "",
           has_uid ? "" : "none:", unsigned(r.uid), r.uid_owner, has_oie ? "yes" : "no",
           unsigned(r.oie_template), unsigned(r.oie_count), mods, r.oie_truncated ? "+" : "",
           hp, r.name, base_flags, (base_flags & offsets::TESFORM_FLAG_UNIQUE_IDS) ? " U" : "",
           static_cast<unsigned long long>(fingerprint(r, true)),
           static_cast<unsigned long long>(fingerprint(r, false)),
           r.quest_item ? " QUEST" : "", r.opaque_types ? " opaque" : "",
           r.unverified_types ? " UNVERIFIED" : "");
}

void dump(void* refr, std::uint32_t base, const char* tag) {
    if (!g_enabled || !refr || !g_base) return;
    using namespace fw::persist::inventory;
    // Main thread only (every caller is), so one buffer serves every dump.
    static ProbeStack stacks[256];
    std::uint32_t reasons = 0;
    const std::uint32_t n = probe_stacks(g_base, refr, base, stacks, 256, &reasons);
    const fw::RefIdentity id = fw::read_ref_identity(refr);
    char only[24] = "";
    if (base) std::snprintf(only, sizeof(only), " of 0x%08X", base);
    FW_LOG("[probe] %s REFR 0x%08X (base 0x%08X cell 0x%08X): %u stack(s)%s%s%s%s",
           tag, id.form_id, id.base_id, id.cell_id, n, only,
           (reasons & REASON_WRITER_HELD) ? ", NOT READ: the engine holds the list's write lock" : "",
           (reasons & REASON_NO_LIST) ? ", no inventory list" : "",
           (reasons & ~(REASON_WRITER_HELD | REASON_NO_LIST)) ? ", read INCOMPLETE" : "");
    for (std::uint32_t i = 0; i < n; ++i) {
        log_stack(tag, stacks[i].r, stacks[i].chain, stacks[i].transient != 0, stacks[i].base_flags);
    }
}

} // namespace fw::persist::probe
