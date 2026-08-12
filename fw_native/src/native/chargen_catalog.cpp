#include "chargen_catalog.h"

#include <windows.h>

#include <algorithm>
#include <atomic>

#include "../log.h"
#include "appearance_recipe.h"

namespace fw::native::catalog {

namespace {

// TESDataHandler, and the form arrays. Same constants chargen_dump walks with.
constexpr std::uintptr_t DATAHANDLER_RVA = 0x030DC000;
constexpr std::size_t    DH_ARRAYS_OFF   = 0x68;
constexpr std::size_t    DH_ARRAY_STRIDE = 0x18;   // {data, capacity, size}
constexpr std::size_t    DH_SIZE_OFF     = 0x10;
constexpr std::uint8_t   FORMTYPE_HDPT   = 15;
constexpr std::uint8_t   FORMTYPE_CLFM   = 137;

constexpr std::size_t FORM_ID_OFF      = 0x14;
constexpr std::size_t FORM_FULLNAME    = 0x28;   // TESFullName component + 8
constexpr std::size_t HDPT_FLAGS       = 0x70;
constexpr std::size_t HDPT_TYPE        = 0x74;
constexpr std::size_t HDPT_VALIDRACES  = 0x160;  // BGSListForm*, null = all
constexpr std::size_t HDPT_EDITORID    = 0x170;

constexpr std::uint32_t HDPT_PLAYABLE  = 0x01;
constexpr std::uint32_t HDPT_MALE      = 0x02;
constexpr std::uint32_t HDPT_FEMALE    = 0x04;
constexpr std::uint32_t HDPT_EXTRAPART = 0x08;

// BGSColorForm. The flags field at +0x40 is what separates a hair colour from a
// tint palette entry, and it was settled from the dump rather than assumed:
//
//   flags  count  +0x30 holds          what it is
//   0x03      31  float 0.582          hair colour  (Playable|RemappingIndex)
//   0x07       1  float                hair colour  (+ExtendedLUT) "Purple Dye"
//   0x01      75  packed RGB           playable palette colour, for tints
//   0x00      59  packed RGB           internal palette colour
//
// The proof is not the flag layout, it is the apply: the vanilla menu's own
// apply-haircolor call in chargen_dump/2026-08-08_refresh_haircolor.log passed
// 0x0019EE61, which is one of the 32. Feeding it one of the other 134 would be
// handing a hair-colour function a tint swatch.
//
// This also fixes what the screen showed: three different forms are all named
// "Dark Brown" — one hair colour and two tint palettes — so an unfiltered list
// had visible duplicates that did different things when clicked. Among the 32
// there are ZERO duplicate names.
constexpr std::size_t   CLFM_FLAGS      = 0x40;
constexpr std::uint32_t CLFM_PLAYABLE   = 0x01;
constexpr std::uint32_t CLFM_REMAP_IDX  = 0x02;

// The engine's own exclusivity test, sub_14061C9A0, inlined rather than called:
//   return a1 > 0 && (a1 <= 4 || a1 == 6 || (unsigned)(a1 - 8) <= 1);
bool is_exclusive(std::int32_t t) noexcept {
    return t > 0 && (t <= 4 || t == 6 ||
                     static_cast<std::uint32_t>(t - 8) <= 1u);
}

void* seh_ptr(const void* at) noexcept {
    if (!at) return nullptr;
    __try { return *reinterpret_cast<void* const*>(at); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

std::uint32_t seh_u32(const void* at) noexcept {
    if (!at) return 0;
    __try { return *reinterpret_cast<const std::uint32_t*>(at); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// BSFixedString is NOT a plain char*. Reading one means calling the engine's own
// accessor, BSFixedString::c_str at RVA 0x167C070, with the ADDRESS of the field
// — not with the pointer stored inside it.
//
// A first version dereferenced the field by hand and walked the bytes. It
// produced exactly the garbage that showed up on screen: "??F-", "?-", "(;F-".
// The working reader in chargen_dump had used the engine accessor all along,
// which is the whole reason its catalogue came out with names like "Anchorage"
// and "The Hornet's Nest".
constexpr std::uintptr_t BSFIXEDSTR_CSTR_RVA = 0x0167C070;
using CStrFn = const char*(__fastcall*)(const void*);
CStrFn g_cstr = nullptr;

bool read_bsfixed(const void* field, char* dst, std::size_t n) noexcept {
    if (!field || !dst || n == 0) return false;
    dst[0] = '\0';
    if (!g_cstr) return false;
    __try {
        // A null entry means the string was never set. Normal on many forms.
        if (!*reinterpret_cast<void* const*>(field)) return false;
        const char* p = g_cstr(field);
        if (!p) return false;
        std::size_t i = 0;
        for (; i + 1 < n && p[i]; ++i) dst[i] = p[i];
        dst[i] = '\0';
        return i > 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        dst[0] = '\0';
        return false;
    }
}

// Tint layout. Every one of these was measured by the offline dumper and is
// quoted from chargen_dump.cpp rather than re-derived; see the header for why the
// type field decides the class.
constexpr std::size_t RACE_TINT_SLOT   = 0x698;   // + 8*sex
constexpr std::size_t GRP_NAME         = 0x00;    // BSFixedString
constexpr std::size_t GRP_TTGE         = 0x0C;
constexpr std::size_t GRP_TPL_DATA     = 0x10;
constexpr std::size_t GRP_TPL_SIZE     = 0x20;
constexpr std::size_t TPL_NAME         = 0x08;    // BSFixedString, TTGP
constexpr std::size_t TPL_TYPE         = 0x18;    // int32
constexpr std::size_t TPL_TINT_ID      = 0x1C;    // uint16 -- never 32 bits
constexpr std::size_t TPL_FLAGS        = 0x1E;    // uint8
constexpr std::size_t TPL_PAL_DATA     = 0x30;    // Palette only
constexpr std::size_t TPL_PAL_SIZE     = 0x40;    // Palette only
constexpr std::size_t PAL_ELEM_STRIDE  = 0x18;
constexpr std::size_t PAL_CLFM         = 0x00;    // BGSColorForm*
constexpr std::size_t PAL_ALPHA        = 0x08;    // float
constexpr std::size_t CLFM_COLOUR      = 0x30;    // packed RGB, or a remap float

std::vector<TintGroup> g_tints;
std::atomic<int>       g_tints_sex{-1};
const std::vector<TintGroup> g_no_tints;

std::uint16_t seh_u16(const void* at) noexcept {
    if (!at) return 0;
    __try { return *reinterpret_cast<const std::uint16_t*>(at); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

std::uint8_t seh_u8(const void* at) noexcept {
    if (!at) return 0;
    __try { return *reinterpret_cast<const std::uint8_t*>(at); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

float seh_f32(const void* at) noexcept {
    if (!at) return 0.0f;
    __try { return *reinterpret_cast<const float*>(at); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0.0f; }
}

std::vector<Option> g_parts[10];      // indexed by PNAM type 0..9
std::vector<Option> g_colours;
std::atomic<int>    g_built_sex{-1};  // -1 none, 0 male, 1 female
const std::vector<Option> g_empty;

// Walk one form array. The callback gets each non-null element.
template <typename F>
std::uint32_t walk(std::uintptr_t base, std::uint8_t form_type, F&& fn) {
    void* handler = seh_ptr(reinterpret_cast<const void*>(base + DATAHANDLER_RVA));
    if (!handler) return 0;
    auto* arr = reinterpret_cast<std::uint8_t*>(handler) + DH_ARRAYS_OFF
              + DH_ARRAY_STRIDE * form_type;
    void* data = seh_ptr(arr);
    const std::uint32_t size = seh_u32(arr + DH_SIZE_OFF);
    if (!data || size == 0 || size > 100000u) return 0;
    std::uint32_t seen = 0;
    for (std::uint32_t i = 0; i < size; ++i) {
        void* form = seh_ptr(reinterpret_cast<std::uint8_t*>(data) + 8u * i);
        if (!form) continue;
        fn(form);
        ++seen;
    }
    return seen;
}

}  // namespace

bool ready(bool female) noexcept {
    return g_built_sex.load(std::memory_order_acquire) == (female ? 1 : 0);
}

const std::vector<Option>& parts_of_type(std::int32_t type) noexcept {
    if (type < 0 || type > 9) return g_empty;
    return g_parts[type];
}

const std::vector<Option>& colours() noexcept { return g_colours; }

bool build(std::uintptr_t module_base, bool female) {
    if (!module_base) return false;
    if (ready(female)) return true;
    g_cstr = reinterpret_cast<CStrFn>(module_base + BSFIXEDSTR_CSTR_RVA);

    for (auto& v : g_parts) v.clear();
    g_colours.clear();

    const std::uint32_t opposite = female ? HDPT_MALE : HDPT_FEMALE;

    const std::uint32_t n_hdpt = walk(module_base, FORMTYPE_HDPT,
        [&](void* form) {
            auto* p = reinterpret_cast<std::uint8_t*>(form);
            const std::uint32_t flags = seh_u32(p + HDPT_FLAGS);
            const auto type = static_cast<std::int32_t>(seh_u32(p + HDPT_TYPE));

            // The vanilla menu's four tests, plus the extra-part exclusion.
            if (!is_exclusive(type))            return;
            if (flags & HDPT_EXTRAPART)         return;
            if (!(flags & HDPT_PLAYABLE))       return;
            if (flags & opposite)               return;
            // Valid-races is a BGSListForm on the PART; null means every race.
            // Not filtered here because the only playable races that carry face
            // data are Human and Ghoul (§29) and a per-race filter would need
            // the race pointer threaded in. Left as a known simplification
            // rather than a silent one.

            Option o;
            o.form_id = seh_u32(p + FORM_ID_OFF);
            o.type    = type;
            char buf[160] = {};
            if (read_bsfixed(p + FORM_FULLNAME, buf, sizeof(buf))) {
                o.name = buf;
            } else if (read_bsfixed(p + HDPT_EDITORID, buf, sizeof(buf))) {
                // Falls back to the editor id, which is always present on HDPT
                // and is more useful than an empty row.
                o.name = buf;
            } else {
                char hex[16];
                std::snprintf(hex, sizeof(hex), "0x%08X", o.form_id);
                o.name = hex;
            }
            if (o.form_id) g_parts[type].push_back(std::move(o));
        });

    const std::uint32_t n_clfm = walk(module_base, FORMTYPE_CLFM,
        [&](void* form) {
            auto* p = reinterpret_cast<std::uint8_t*>(form);
            const std::uint32_t flags = seh_u32(p + CLFM_FLAGS);
            // Hair colours only: a remapping index the hair shader can use, and
            // playable. Everything else in this array is a tint swatch.
            if (!(flags & CLFM_REMAP_IDX)) return;
            if (!(flags & CLFM_PLAYABLE))  return;

            Option o;
            o.form_id = seh_u32(p + FORM_ID_OFF);
            char buf[160] = {};
            if (read_bsfixed(p + FORM_FULLNAME, buf, sizeof(buf))) o.name = buf;
            if (o.form_id && !o.name.empty()) g_colours.push_back(std::move(o));
        });

    if (n_hdpt == 0) {
        // The data handler is not populated yet. Say nothing and let the caller
        // try again next tick; this is normal during load.
        return false;
    }

    // Alphabetical. The array order is load order, which is meaningless to a
    // player looking for a hairstyle by name.
    for (auto& v : g_parts) {
        std::sort(v.begin(), v.end(), [](const Option& a, const Option& b) {
            return a.name < b.name;
        });
    }
    std::sort(g_colours.begin(), g_colours.end(),
              [](const Option& a, const Option& b) { return a.name < b.name; });

    g_built_sex.store(female ? 1 : 0, std::memory_order_release);
    FW_LOG("[catalog] built for %s from %u head part(s) and %u colour form(s): "
           "hair=%zu eyes=%zu beard=%zu face=%zu teeth=%zu rear=%zu colours=%zu",
           female ? "FEMALE" : "MALE", n_hdpt, n_clfm,
           g_parts[3].size(), g_parts[2].size(), g_parts[4].size(),
           g_parts[1].size(), g_parts[8].size(), g_parts[9].size(),
           g_colours.size());
    return true;
}


const std::vector<TintGroup>& tint_groups() noexcept {
    if (g_tints_sex.load(std::memory_order_acquire) < 0) return g_no_tints;
    return g_tints;
}

const TintGroup* tint_group(const char* name) noexcept {
    if (!name || g_tints_sex.load(std::memory_order_acquire) < 0) return nullptr;
    for (const auto& g : g_tints) {
        if (g.name == name) return &g;
    }
    return nullptr;
}

// Says WHY the walk could not run, once every few seconds. Written because the
// first attempt returned false from one of five places and every one of them was
// silent, which turns a two-minute question into a guessing game.
bool tint_bail(const char* why) noexcept {
    static DWORD s_last = 0;
    const DWORD now = GetTickCount();
    if (now - s_last >= 4000) {
        s_last = now;
        FW_LOG("[catalog] tint walk not ready: %s (throttled to 1/4s)", why);
    }
    return false;
}

bool build_tints(std::uintptr_t module_base) {
    if (!module_base) return false;
    void* npc = ::fw::native::appearance::player_npc(module_base);
    if (!npc) return tint_bail("no player TESNPC");
    const bool female = ::fw::native::appearance::npc_is_female(npc);
    if (g_tints_sex.load(std::memory_order_acquire) == (female ? 1 : 0)) {
        return true;
    }
    void* race = ::fw::native::appearance::npc_race(npc);
    if (!race) return tint_bail("TESNPC+0x1B8 (race) is null");
    g_cstr = reinterpret_cast<CStrFn>(module_base + BSFIXEDSTR_CSTR_RVA);

    // TWO DEREFERENCES, not one, and the difference was worth a build to learn.
    //
    // re/chargen_editor_data_AGENT.md describes the chain as
    // "race + 0x698 + 8*sex -> CharGenData*", i.e. one indirection, and following
    // that produced a plausible-looking data pointer with a group count of
    // 2702387760. The offline dumper walks it as slot then container, and its
    // recorded TINT-CHAIN line settles it with actual numbers:
    //
    //   sex=0  race+0x698  slot=..41BE8888  container=..41DAEC60
    //          +00=<data>  +08=0x10 (capacity 16)  +10=0x09 (nine groups)
    //   sex=1  race+0x6A0                          +10=0x0A (ten groups)
    //
    // Nine groups for a male and ten for a female is exactly what the group dump
    // shows, so the two-level chain is the verified one and the dossier's
    // one-level summary is wrong. Measurements beat prose.
    auto* rp = reinterpret_cast<std::uint8_t*>(race);
    void* slot = seh_ptr(rp + RACE_TINT_SLOT + 8u * (female ? 1u : 0u));
    void* cgd  = slot ? seh_ptr(slot) : nullptr;
    if (!cgd) {
        // Built lazily by TESRace::Load; a null here means it is not there yet
        // rather than that it does not exist. Caller retries.
        return tint_bail("race+0x698+8*sex holds no CharGenData yet");
    }

    auto* cg = reinterpret_cast<std::uint8_t*>(cgd);
    void* gdata = seh_ptr(cg);                       // BSTArray data at +0x00
    const std::uint32_t gcount = seh_u32(cg + 0x10);
    if (!gdata || gcount == 0 || gcount > 64u) {
        char msg[128];
        std::snprintf(msg, sizeof(msg),
                      "CharGenData group array looks wrong: data=%p size=%u",
                      gdata, gcount);
        return tint_bail(msg);
    }

    g_tints.clear();
    g_tints.reserve(gcount);

    std::size_t tpl_total = 0, col_total = 0;
    for (std::uint32_t i = 0; i < gcount; ++i) {
        void* grp = seh_ptr(reinterpret_cast<std::uint8_t*>(gdata) + 8u * i);
        if (!grp) continue;
        auto* g = reinterpret_cast<std::uint8_t*>(grp);

        TintGroup out;
        char buf[160] = {};
        if (read_bsfixed(g + GRP_NAME, buf, sizeof(buf))) out.name = buf;
        out.ttge = seh_u32(g + GRP_TTGE);

        void* tdata = seh_ptr(g + GRP_TPL_DATA);
        const std::uint32_t tcount = seh_u32(g + GRP_TPL_SIZE);
        if (tdata && tcount > 0 && tcount <= 4096u) {
            out.items.reserve(tcount);
            for (std::uint32_t j = 0; j < tcount; ++j) {
                void* tpl = seh_ptr(reinterpret_cast<std::uint8_t*>(tdata)
                                    + 8u * j);
                if (!tpl) continue;
                auto* tp = reinterpret_cast<std::uint8_t*>(tpl);

                TintOption o;
                o.type    = static_cast<std::int32_t>(seh_u32(tp + TPL_TYPE));
                o.tint_id = seh_u16(tp + TPL_TINT_ID);
                o.flags   = seh_u8 (tp + TPL_FLAGS);
                o.palette = (o.type >= 7 && o.type <= 20);
                if (read_bsfixed(tp + TPL_NAME, buf, sizeof(buf))) o.name = buf;
                if (o.name.empty()) o.name = "Default";
                if (o.tint_id == 0) continue;   // no key, cannot be applied

                if (o.palette) {
                    void* pdata = seh_ptr(tp + TPL_PAL_DATA);
                    const std::uint32_t pcount = seh_u32(tp + TPL_PAL_SIZE);
                    if (pdata && pcount > 0 && pcount <= 4096u) {
                        o.colours.reserve(pcount);
                        for (std::uint32_t k = 0; k < pcount; ++k) {
                            auto* el = reinterpret_cast<std::uint8_t*>(pdata)
                                     + PAL_ELEM_STRIDE * k;
                            void* clfm = seh_ptr(el + PAL_CLFM);
                            if (!clfm) continue;
                            auto* cf = reinterpret_cast<std::uint8_t*>(clfm);

                            TintColour c;
                            c.clfm_form_id = seh_u32(cf + FORM_ID_OFF);
                            c.alpha        = seh_f32(el + PAL_ALPHA);
                            // The remap flag matters here for the same reason it
                            // matters for hair: on a remapping form +0x30 holds a
                            // float, and reading it as a packed colour yields a
                            // denormal painted as near-black.
                            const std::uint32_t cflags = seh_u32(cf + CLFM_FLAGS);
                            c.rgb = (cflags & CLFM_REMAP_IDX)
                                  ? 0u : seh_u32(cf + CLFM_COLOUR);
                            if (read_bsfixed(cf + FORM_FULLNAME, buf,
                                             sizeof(buf))) {
                                c.name = buf;
                            }
                            if (c.name.empty()) {
                                char hex[16];
                                std::snprintf(hex, sizeof(hex), "0x%08X",
                                              c.clfm_form_id);
                                c.name = hex;
                            }
                            o.colours.push_back(std::move(c));
                        }
                    }
                }
                col_total += o.colours.size();
                ++tpl_total;
                out.items.push_back(std::move(o));
            }
        }
        g_tints.push_back(std::move(out));
    }

    g_tints_sex.store(female ? 1 : 0, std::memory_order_release);
    FW_LOG("[catalog] tints built for %s: %zu group(s), %zu template(s), "
           "%zu palette colour(s)", female ? "FEMALE" : "MALE",
           g_tints.size(), tpl_total, col_total);
    for (const auto& g : g_tints) {
        std::size_t pal = 0, mask = 0, cols = 0;
        for (const auto& it : g.items) {
            if (it.palette) { ++pal; cols += it.colours.size(); } else ++mask;
        }
        FW_LOG("[catalog]   group '%s' ttge=%u -> %zu template(s) "
               "(%zu palette / %zu mask), %zu colour(s)",
               g.name.c_str(), g.ttge, g.items.size(), pal, mask, cols);
    }
    return true;
}

}  // namespace fw::native::catalog
