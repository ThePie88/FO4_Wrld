#include "chargen_dump.h"

#include <windows.h>

#include <intrin.h>   // _ReturnAddress for caller-RIP capture

#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>

#include "../hook_manager.h"
#include "../log.h"

namespace fw::native::chargen_dump {

namespace {

std::atomic<bool>          g_on{false};
std::atomic<std::uint64_t> g_records{0};
std::mutex                 g_mtx;
HANDLE                     g_file  = INVALID_HANDLE_VALUE;
std::uint64_t              g_t0    = 0;

}  // namespace

void init(const std::wstring& dir, bool enabled) {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (!enabled) {
        g_on.store(false, std::memory_order_relaxed);
        return;
    }
    const std::wstring path = dir + L"\\fw_chargen_dump.log";
    g_file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                         nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                         nullptr);
    if (g_file == INVALID_HANDLE_VALUE) {
        FW_ERR("[chargen-dump] could not open fw_chargen_dump.log — capture "
               "disabled");
        return;
    }
    g_t0 = GetTickCount64();
    g_on.store(true, std::memory_order_relaxed);

    const char* hdr =
        "# FO4_Wrld character-creation asset dump\r\n"
        "# One record per line, tab separated: <ms>\\t<kind>\\t<fields>\r\n"
        "# Capture everything, organise later.\r\n";
    DWORD w = 0;
    WriteFile(g_file, hdr, static_cast<DWORD>(std::strlen(hdr)), &w, nullptr);

    FW_LOG("[chargen-dump] CAPTURE ARMED -> fw_chargen_dump.log. Open the "
           "character-creation menu and cycle every preset, category and "
           "slider; everything the engine loads is recorded.");
}

bool enabled() noexcept {
    return g_on.load(std::memory_order_relaxed);
}

std::uint64_t records() noexcept {
    return g_records.load(std::memory_order_relaxed);
}

void note(const char* kind, const char* detail) noexcept {
    if (!g_on.load(std::memory_order_relaxed)) return;
    if (!kind) kind = "?";
    if (!detail) detail = "";

    char line[1200];
    const std::uint64_t ms = GetTickCount64() - g_t0;
    const int n = std::snprintf(line, sizeof(line), "%llu\t%s\t%s\r\n",
                                static_cast<unsigned long long>(ms),
                                kind, detail);
    if (n <= 0) return;

    std::lock_guard<std::mutex> lk(g_mtx);
    if (g_file == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(g_file, line,
              static_cast<DWORD>(n < static_cast<int>(sizeof(line))
                                     ? n : sizeof(line) - 1),
              &w, nullptr);
    g_records.fetch_add(1, std::memory_order_relaxed);
}

void note_resource(const char* kind, const char* path) noexcept {
    if (!g_on.load(std::memory_order_relaxed)) return;
    if (!path || !*path) return;
    char detail[1024];
    std::snprintf(detail, sizeof(detail), "path=%s", path);
    note(kind, detail);
}

// ===========================================================================
// Capture points. All offsets and RVAs are from the 2026-08-06 RE pass; the
// reasoning for each is in CHARGEN_PLAN.md §8.
// ===========================================================================

namespace {

// --- engine addresses ------------------------------------------------------
// Deliberately NOT hooked (see install()): 0x6A6D00 resource-DB load,
// 0x6A83B0 file stream. Both run on boot streaming threads.
constexpr std::uintptr_t LOOKSMENU_CALL_RVA = 0x00A82490; // every UI callback
constexpr std::uintptr_t NPC_SETMORPH_RVA   = 0x00654310; // every facial morph
constexpr std::uintptr_t ADD_HEADPART_RVA   = 0x00655010;
constexpr std::uintptr_t SET_HAIRCOLOR_RVA  = 0x00654DF0;
constexpr std::uintptr_t BSFIXEDSTR_CSTR_RVA = 0x0167C070;

// Blocker #1 observation (2026-08-08). Static RE (CHARGEN_PLAN §13) traced
// the head rebuild to these two, but left the identity of the first
// argument of HEAD_BUILD open. Guessing it is exactly what went wrong twice
// already, so observe instead: log the real arguments and let one ordinary
// session say what the context object is.
//   HEAD_BUILD(a1, a2): gates on a1+0x60 (TESNPC) and a1+0x78 non-null and
//     a2+0x1A == 65 (the actor reference's form type). Leads, via
//     sub_1406E2260 -> sub_1406ED9C0 -> sub_140658B20, to the
//     "FaceGenData\FaceGeom\%s\%08X.NIF" load.
//   APPEARANCE_TASK(a1, a2, a3, a4): the chargen menu's deferred update —
//     builds an 0x80-byte record tagged 0x75 and posts it.
constexpr std::uintptr_t HEAD_BUILD_RVA      = 0x006E03E0;
constexpr std::uintptr_t APPEARANCE_TASK_RVA = 0x00C4BA90;
// 2026-08-08 second pass. Eye colour posts a task; HAIR colour does not —
// it raises a dirty byte consumed by sub_140BC0690, which calls REFRESH.
// Two different levers, so instrument both, plus the queue constructor
// whose caller names what triggers a rebuild in ordinary play.
constexpr std::uintptr_t REFRESH_RVA         = 0x006DFB00;
constexpr std::uintptr_t QUEUED_HEAD_CTOR_RVA = 0x002C60B0;

constexpr std::uintptr_t DATAHANDLER_RVA    = 0x030DC000;
constexpr std::size_t    DH_ARRAYS_OFF      = 0x68;   // BSTArray<TESForm*>[159]
constexpr std::size_t    DH_ARRAY_STRIDE    = 0x18;   // data / capacity / size

// TESForm / BGSHeadPart layout
constexpr std::size_t FORM_ID_OFF      = 0x14;
constexpr std::size_t FORM_TYPE_OFF    = 0x1A;
constexpr std::size_t HDPT_FULLNAME    = 0x28;
constexpr std::size_t HDPT_MODEL       = 0x38;   // BSFixedString .nif path
constexpr std::size_t HDPT_FLAGS       = 0x70;
constexpr std::size_t HDPT_PNAM        = 0x74;   // part type
constexpr std::size_t HDPT_EXTRA_DATA  = 0x78;   // BSTArray<BGSHeadPart*>
constexpr std::size_t HDPT_EXTRA_SIZE  = 0x88;
constexpr std::size_t HDPT_MORPH0      = 0xC8;   // three TESModelTri slots,
constexpr std::size_t HDPT_MORPH_STRIDE = 0x30;  //   path at slot + 0x08
constexpr std::size_t HDPT_COLOR       = 0x158;
constexpr std::size_t HDPT_EDITORID    = 0x170;

constexpr std::uint8_t FORMTYPE_HDPT = 15;
constexpr std::uint8_t FORMTYPE_RACE = 17;
constexpr std::uint8_t FORMTYPE_CLFM = 137;

// --- face tints ------------------------------------------------------------
// War paint, makeup, dirt, freckles, overlay scars: the whole "extras" half of
// the creation menu. None of it is a head part — they are
// BGSCharacterTint::Template::* objects hanging off TESRace, so the head-part
// catalogue is structurally blind to them.
//
// Where they hang off the race is the open question. The vtable RVAs below are
// solid (re/engine_rtti_catalog.md, from the IDA database), but nothing in the
// decompilation dumps references them, so there is no read of the layout to
// copy. Rather than guess an offset and get another silent zero, the probe
// walks the race object and follows pointers until one lands on a known
// template vtable. Whatever it prints IS the layout.
constexpr std::uintptr_t VT_TPL_ENTRY   = 0x0247FD08;
constexpr std::uintptr_t VT_TPL_MASK    = 0x0247FD38;
constexpr std::uintptr_t VT_TPL_PALETTE = 0x0247FD68;
constexpr std::uintptr_t VT_TPL_TEXSET  = 0x0247FD98;
// The applied-instance classes, for completeness — an NPC holds these, a race
// holds the templates above.
constexpr std::uintptr_t VT_ENTRY       = 0x0247FC08;
constexpr std::uintptr_t VT_MASK_ENTRY  = 0x0247FC48;
constexpr std::uintptr_t VT_PAL_ENTRY   = 0x0247FC88;
constexpr std::uintptr_t VT_TEX_ENTRY   = 0x0247FCC8;

constexpr std::uint32_t  HUMAN_RACE_FID = 0x00013746;
constexpr std::size_t    RACE_SCAN_BYTES   = 0x2000; // first pass said 0x1000
constexpr std::size_t    STRUCT_SCAN_BYTES = 0x200;  // second level
constexpr std::size_t    DEEP_SCAN_BYTES   = 0x80;   // third level
constexpr int            TINT_PROBE_TRIES  = 60;     // ~5 min at 5 s apart

void*          g_human_race = nullptr;
std::uintptr_t g_module     = 0;

const char* const kPartType[] = {
    "Misc", "Face", "Eyes", "Hair", "FacialHair", "Scar",
    "Eyebrows", "Meatcaps", "Teeth", "HeadRear"
};

using HeadBuildFn      = void*(__fastcall*)(void*, void*);
// FULL arities, taken from the pseudo-C signatures — NOT guessed.
// A shorter signature crashed the 2026-08-08 02:00 session: on x64 every
// argument past the fourth lives on the stack, so chaining through a
// truncated prototype leaves those slots uninitialised and the original
// function reads garbage. Verify arity in 10_decomp BEFORE hooking anything.
//   sub_1406DFB00(a1,a2,a3,a4,a5,a6,a7,a8,a9)          - 9
//   sub_1402C60B0(a1,a2,a3,a4,a5)                      - 5
using RefreshFn        = void*(__fastcall*)(void*, void*, void*, void*,
                                            std::uint64_t, std::uint64_t,
                                            std::uint64_t, std::uint64_t,
                                            std::uint64_t);
using QueuedHeadFn     = void*(__fastcall*)(void*, void*, void*,
                                            std::uint32_t, std::uint64_t);
using AppearanceTaskFn = void*(__fastcall*)(void*, void*, void*, void*);
using LooksMenuFn    = void(__fastcall*)(void*, void*);
using SetMorphFn     = void(__fastcall*)(void*, std::uint32_t, float);
using AddHeadPartFn  = void(__fastcall*)(void*, void*, bool, bool, bool);
using SetHairColorFn = void(__fastcall*)(void*, void*);
using CStrFn         = const char*(__fastcall*)(const void*);

HeadBuildFn      g_orig_head_build  = nullptr;
RefreshFn        g_orig_refresh     = nullptr;
QueuedHeadFn     g_orig_queued_head = nullptr;
AppearanceTaskFn g_orig_appr_task  = nullptr;
LooksMenuFn    g_orig_looksmenu   = nullptr;
SetMorphFn     g_orig_setmorph    = nullptr;
AddHeadPartFn  g_orig_addheadpart = nullptr;
SetHairColorFn g_orig_haircolor   = nullptr;
CStrFn         g_cstr             = nullptr;

std::atomic<bool> g_catalogue_done{false};

// SEH-caged string copy out of engine memory.
bool safe_str(const char* src, char* dst, std::size_t n) noexcept {
    if (!src || !dst || n == 0) return false;
    __try {
        std::size_t i = 0;
        for (; i + 1 < n && src[i]; ++i) dst[i] = src[i];
        dst[i] = 0;
        return i > 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) { dst[0] = 0; return false; }
}

// BSFixedString in this build is a BSStringPool::Entry*, NOT a char*. The
// engine's own c_str returns entry+0x18 (wide strings take another path,
// which the accessor handles) — so go through it rather than guessing.
bool read_bsfixed(const void* field, char* dst, std::size_t n) noexcept {
    if (!g_cstr) return false;
    __try {
        const void* entry = *reinterpret_cast<void* const*>(field);
        if (!entry) { if (n) dst[0] = 0; return false; }
        return safe_str(g_cstr(field), dst, n);
    } __except (EXCEPTION_EXECUTE_HANDLER) { if (n) dst[0] = 0; return false; }
}

// --- pointer-chasing helpers for the tint probe ----------------------------
// A raw scan over an engine object reads a lot of garbage. Filter on shape
// first (canonical user-space address, 8-aligned) so SEH is the exception and
// not the mechanism, then guard the read anyway.
bool plausible_ptr(const void* p) noexcept {
    const auto v = reinterpret_cast<std::uintptr_t>(p);
    return v > 0x10000 && v < 0x00007FFFFFFFFFFFULL && (v & 7) == 0;
}

void* safe_deref(const void* addr) noexcept {
    if (!plausible_ptr(addr)) return nullptr;
    __try { return *reinterpret_cast<void* const*>(addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

// Read obj's vtable and name it if it is one of the tint classes.
const char* tint_class_of(std::uintptr_t base, const void* obj) noexcept {
    if (!plausible_ptr(obj)) return nullptr;
    void* vt = safe_deref(obj);
    if (!vt) return nullptr;
    const auto v = reinterpret_cast<std::uintptr_t>(vt);
    if (v <= base) return nullptr;
    switch (v - base) {
        case VT_TPL_ENTRY:   return "Template::Entry";
        case VT_TPL_MASK:    return "Template::Mask";
        case VT_TPL_PALETTE: return "Template::Palette";
        case VT_TPL_TEXSET:  return "Template::TextureSet";
        case VT_ENTRY:       return "Entry";
        case VT_MASK_ENTRY:  return "MaskEntry";
        case VT_PAL_ENTRY:   return "PaletteEntry";
        case VT_TEX_ENTRY:   return "TextureSetEntry";
        default:             return nullptr;
    }
}

std::uint32_t seh_read_u32(const void* addr) noexcept {
    __try { return *reinterpret_cast<const std::uint32_t*>(addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

float seh_read_f32(const void* addr) noexcept {
    __try { return *reinterpret_cast<const float*>(addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0.0f; }
}

std::uint16_t seh_read_u16(const void* addr) noexcept {
    __try { return *reinterpret_cast<const std::uint16_t*>(addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

std::uint8_t seh_read_u8(const void* addr) noexcept {
    __try { return *reinterpret_cast<const std::uint8_t*>(addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

std::uint32_t form_id(const void* form) noexcept {
    __try {
        return *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(form) + FORM_ID_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// Walk the race object looking for anything that reaches a tint template.
// Three shapes are tried per slot, cheapest first:
//   A  race+o is itself a template object
//   B  race+o is an array's data pointer, so *(race+o) is the first element
//   C  race+o is an intermediate struct (the per-sex chargen block, most
//      likely) holding the array somewhere in its first 0x200 bytes
// Every hit is reported rather than just the first: knowing there are two
// parallel blocks is what tells us the data is split by sex.
// The blind scan below found nothing, so the offset was read out of the
// engine instead. sub_140400F80 is the RACE tint parser: it walks the record
// looking for the 'TETI' and 'TTGE' subrecords, builds a
// BGSCharacterTint::Template::* per entry through the factory at
// sub_1403FFF70, and appends it to an array. Its call site at 0x140688891
// shows where that array hangs:
//
//     mov rax, [r15+rsi*8+698h]     ; r15 = race, rsi = sex (0/1)
//     mov [rax], rdi                ; the freshly allocated container
//     mov rcx, [r15+rsi*8+698h]
//     mov rcx, [rcx]                ; -> container
//     call sub_1403FFD80            ; -> group within the container
//     call sub_140400F80            ; fills group+0x10 with Entry*
//
// So race+0x698+8*sex is a pointer to a slot holding the per-sex tint
// container. Read it directly and print the chain raw — if it is null the
// data is built lazily, and no amount of scanning would have found it.
constexpr std::size_t RACE_TINT_SLOT = 0x698;
// TESRace, 2026-08-08. Editor ids are a TESForm virtual (slot 58, +0x1D0) and
// the base implementation throws the value away, so each of the 18 classes that
// keeps one keeps it somewhere different. BGSHeadPart uses +0x170 — which is why
// reading that offset worked for HDPT and produced only handled AVs elsewhere.
constexpr std::size_t   RACE_EDITORID     = 0x3A0;
constexpr std::size_t   RACE_FULLNAME     = 0x28;   // TESFullName component +8
constexpr std::size_t   RACE_DATA_FLAGS   = 0x1A0;
constexpr std::uint32_t RACE_FLAG_PLAYABLE = 0x01;

// Layout below is measured, not guessed — the exploratory walk printed it:
//
//   container +0x00  BSTArray<Group*>  {data, capacity, size}   the groups
//                    male: cap 16 size 9      female: cap 16 size 10
//   Group is 0x28 bytes, and only three of its fields matter here:
//   group     +0x10  Template**      array data
//             +0x18  capacity
//             +0x20  size
//
// 2026-08-08 CORRECTED. The earlier layout note here was wrong in two ways and
// the dump has been carrying the consequences: it printed tex1/tex2 for every
// class, and it called +0x18 an "index".
//
// The three template classes share a 0x20-byte header and then differ, and the
// class is selected by the TYPE at +0x18 — factory sub_1403FFF70: type < 7 is
// Mask (0x30 bytes), 7..20 Palette (0x48), >= 21 TextureSet (0x40). Confirmed
// against all 306 captured records with no exceptions.
//
//   SHARED   +0x00 vtable
//            +0x08 BSFixedString name (defaults to "Default")
//            +0x10 TESCondition
//            +0x18 int32  TYPE      <- the stable semantic id; 12 IS SKIN TONE
//            +0x1C uint16 tint id   <- the key for sub_14065DAB0, 16 BITS
//            +0x1E uint8  flags (bit0 = binary on/off, intensity forced to 1)
//            +0x1F uninitialised padding — never read +0x1C as 32 bits
//   Mask     +0x20 BSFixedString mask texture   +0x28 int32 blend mode 0..4
//   Palette  +0x20 BSFixedString mask texture   +0x28 int32 default colour idx
//            +0x30/+0x38/+0x40 BSTArray<PaletteColor>, element stride 0x18
//   TexSet   +0x20/+0x28/+0x30 three BSFixedString texture paths
//
// So +0x28 is an int32 on Mask and Palette, and on Palette +0x30 is an array
// data pointer. Reading those as strings is what produced the garbage tex1/tex2
// values in every Mask and Palette line of the 2026-08-07 catalogue.
constexpr std::size_t TINT_GROUPS_OFF  = 0x00;
constexpr std::size_t GRP_NAME         = 0x00;   // never read until now
constexpr std::size_t GRP_TTGE         = 0x0C;
constexpr std::size_t GRP_TPL_DATA     = 0x10;
constexpr std::size_t GRP_TPL_SIZE     = 0x20;
constexpr std::size_t TPL_NAME         = 0x08;
constexpr std::size_t TPL_COND         = 0x10;
constexpr std::size_t TPL_TYPE         = 0x18;
constexpr std::size_t TPL_TINT_ID      = 0x1C;   // uint16
constexpr std::size_t TPL_FLAGS        = 0x1E;   // uint8
constexpr std::size_t TPL_TEX0         = 0x20;
constexpr std::size_t TPL_TEX_STRIDE   = 0x08;
constexpr std::size_t TPL_MASK_BLEND   = 0x28;   // Mask only, int32
constexpr std::size_t TPL_PAL_DEFAULT  = 0x28;   // Palette only, int32
constexpr std::size_t TPL_PAL_DATA     = 0x30;   // Palette only, array data
constexpr std::size_t TPL_PAL_SIZE     = 0x40;   // Palette only, count
constexpr std::size_t PAL_ELEM_STRIDE  = 0x18;
constexpr std::size_t PAL_CLFM         = 0x00;   // BGSColorForm*
constexpr std::size_t PAL_ALPHA        = 0x08;   // float
constexpr std::size_t PAL_MODE         = 0x0C;   // uint32, 0..4
constexpr std::size_t PAL_COLOUR_ID    = 0x10;   // uint16
// BGSColorForm: +0x28 display name, +0x30 a UNION (packed RGB when the FNAM
// flags at +0x40 do NOT have bit 0x02, a float remap index when they do).
constexpr std::size_t CLFM_NAME        = 0x28;
constexpr std::size_t CLFM_VALUE       = 0x30;
constexpr std::size_t CLFM_FLAGS       = 0x40;
constexpr std::uint32_t CLFM_FLAG_REMAP = 0x02;

// The type ranges the factory uses to pick a class. Kept as a helper because
// the type is a more trustworthy discriminator than the vtable: it is what the
// engine itself switches on.
const char* tint_class_from_type(std::int32_t type) noexcept {
    if (type < 7)  return "Mask";
    if (type < 21) return "Palette";
    return "TextureSet";
}

std::uint32_t dump_tint_groups(std::uintptr_t base, void* container,
                               int sex) noexcept {
    auto* c = reinterpret_cast<std::uint8_t*>(container) + TINT_GROUPS_OFF;
    void*         groups = safe_deref(c);
    std::uint32_t n_groups = 0;
    __try {
        n_groups = *reinterpret_cast<std::uint32_t*>(c + 0x10);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    if (!groups || n_groups == 0 || n_groups > 256) return 0;

    std::uint32_t written = 0;
    for (std::uint32_t g = 0; g < n_groups; ++g) {
        void* group = safe_deref(
            reinterpret_cast<std::uint8_t*>(groups) + 8u * g);
        if (!group) continue;
        auto* gp = reinterpret_cast<std::uint8_t*>(group);

        // The group's own name, at +0x00. Loaded from the TTGP payload by the
        // same string loader TESFullName uses, so it is a display string. Never
        // printed before, and it is what decides whether the editor can label
        // its tint categories from data instead of hardcoding "group 2 is
        // eyebrows, group 4 is skin tone".
        char gname[160] = {};
        read_bsfixed(gp + GRP_NAME, gname, sizeof(gname));
        {
            char gd[256];
            std::snprintf(gd, sizeof(gd),
                          "sex=%d\tgroup=%u\tname=%s\tttge=%u",
                          sex, g, gname[0] ? gname : "(empty)",
                          seh_read_u32(gp + GRP_TTGE));
            note("TINT-GROUP", gd);
        }

        void*         tpl_data = safe_deref(gp + GRP_TPL_DATA);
        std::uint32_t n_tpl    = 0;
        __try {
            n_tpl = *reinterpret_cast<std::uint32_t*>(gp + GRP_TPL_SIZE);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        if (!tpl_data || n_tpl == 0 || n_tpl > 4096) continue;

        for (std::uint32_t t = 0; t < n_tpl; ++t) {
            void* tpl = safe_deref(
                reinterpret_cast<std::uint8_t*>(tpl_data) + 8u * t);
            const char* cls = tint_class_of(base, tpl);
            if (!cls) continue;

            auto* p = reinterpret_cast<std::uint8_t*>(tpl);
            char name[160] = {};
            read_bsfixed(p + TPL_NAME, name, sizeof(name));

            const std::int32_t  type    =
                static_cast<std::int32_t>(seh_read_u32(p + TPL_TYPE));
            const std::uint16_t tint_id = seh_read_u16(p + TPL_TINT_ID);
            const std::uint8_t  tflags  = seh_read_u8(p + TPL_FLAGS);
            const bool          has_cond= safe_deref(p + TPL_COND) != nullptr;

            // tex0 is a real BSFixedString on Mask and Palette (the mask
            // texture) and on TextureSet (the first of three). Everything past
            // it is class-specific, which is exactly what the old code got
            // wrong.
            char tex0[288] = {};
            read_bsfixed(p + TPL_TEX0, tex0, sizeof(tex0));

            char extra[512] = {};
            if (type >= 21) {
                char tex1[288] = {}, tex2[288] = {};
                read_bsfixed(p + TPL_TEX0 + TPL_TEX_STRIDE, tex1, sizeof(tex1));
                read_bsfixed(p + TPL_TEX0 + TPL_TEX_STRIDE * 2, tex2,
                             sizeof(tex2));
                std::snprintf(extra, sizeof(extra), "\ttex1=%s\ttex2=%s",
                              tex1, tex2);
            } else if (type < 7) {
                std::snprintf(extra, sizeof(extra), "\tblend=%u",
                              seh_read_u32(p + TPL_MASK_BLEND));
            } else {
                std::snprintf(extra, sizeof(extra), "\tdefault_colour=%d"
                              "\tcolours=%u",
                              static_cast<std::int32_t>(
                                  seh_read_u32(p + TPL_PAL_DEFAULT)),
                              seh_read_u32(p + TPL_PAL_SIZE));
            }

            char d[1024];
            std::snprintf(d, sizeof(d),
                          "sex=%d\tgroup=%u\tgroup_name=%s\tslot_in_group=%u"
                          "\tvt=%s\tclass=%s\ttype=%d\ttint_id=%u\tflags=0x%02X"
                          "\tcond=%d\tname=%s\ttex0=%s%s",
                          sex, g, gname[0] ? gname : "(empty)", t,
                          cls, tint_class_from_type(type), type, tint_id,
                          tflags, has_cond ? 1 : 0, name, tex0, extra);
            note("TINT", d);
            ++written;

            // A Palette carries the selectable colours, and one of those
            // palettes IS the skin tone (the template whose type == 12). The
            // colour list was never dumped, so "how many skin tones exist" has
            // been an open question that only the data can answer.
            if (type >= 7 && type < 21) {
                void* pal = safe_deref(p + TPL_PAL_DATA);
                const std::uint32_t n_col = seh_read_u32(p + TPL_PAL_SIZE);
                if (pal && n_col && n_col <= 512) {
                    for (std::uint32_t ci = 0; ci < n_col; ++ci) {
                        auto* e = reinterpret_cast<std::uint8_t*>(pal)
                                + PAL_ELEM_STRIDE * ci;
                        void* clfm = safe_deref(e + PAL_CLFM);
                        char cname[160] = {};
                        std::uint32_t cflags = 0, cvalue = 0, cfid = 0;
                        if (clfm) {
                            auto* c2 = reinterpret_cast<std::uint8_t*>(clfm);
                            read_bsfixed(c2 + CLFM_NAME, cname, sizeof(cname));
                            cflags = seh_read_u32(c2 + CLFM_FLAGS);
                            cvalue = seh_read_u32(c2 + CLFM_VALUE);
                            cfid   = form_id(clfm);
                        }
                        const bool remap = (cflags & CLFM_FLAG_REMAP) != 0;
                        char cd[640];
                        std::snprintf(cd, sizeof(cd),
                            "sex=%d\tgroup=%u\ttype=%d\ttint_id=%u\tidx=%u"
                            "\tclfm=0x%08X\tname=%s\tclfm_flags=0x%02X"
                            "\t%s=0x%08X\talpha=%.3f\tmode=%u\tcolour_id=%u",
                            sex, g, type, tint_id, ci, cfid,
                            cname[0] ? cname : "(none)", cflags,
                            remap ? "remap_bits" : "packed_rgb", cvalue,
                            seh_read_f32(e + PAL_ALPHA),
                            seh_read_u32(e + PAL_MODE),
                            seh_read_u16(e + PAL_COLOUR_ID));
                        note("TINT-COLOUR", cd);
                    }
                }
            }
        }
    }
    return written;
}

void dump_tint_chain(std::uintptr_t base, void* race) noexcept {
    auto* r = reinterpret_cast<std::uint8_t*>(race);
    std::uint32_t n_tints = 0;
    for (int sex = 0; sex < 2; ++sex) {
        void* slot      = safe_deref(r + RACE_TINT_SLOT + 8u * sex);
        void* container = slot ? safe_deref(slot) : nullptr;
        char d[512];
        int  w = std::snprintf(d, sizeof(d),
                               "sex=%d\trace+0x%03zX\tslot=%p\tcontainer=%p",
                               sex, RACE_TINT_SLOT + 8u * sex, slot, container);
        if (container) {
            // First 0x40 bytes of the container, so the array triple can be
            // located from the log without another build.
            for (std::size_t o = 0; o < 0x40 && w > 0 &&
                                    w < static_cast<int>(sizeof(d)) - 24;
                 o += 8) {
                void* q = safe_deref(
                    reinterpret_cast<std::uint8_t*>(container) + o);
                const char* cls = tint_class_of(base, q);
                if (!cls) cls = tint_class_of(base, safe_deref(q));
                w += std::snprintf(d + w, sizeof(d) - w, "\t+%02zX=%p%s%s",
                                   o, q, cls ? ":" : "", cls ? cls : "");
            }
        }
        note("TINT-CHAIN", d);
        FW_LOG("[chargen-dump] tint chain: %s", d);
        if (!container) continue;
        n_tints += dump_tint_groups(base, container, sex);
    }
    if (n_tints) {
        FW_LOG("[chargen-dump] face tints written: %u templates across both "
               "sexes", n_tints);
    } else {
        FW_WRN("[chargen-dump] face tints: chain reached but no template "
               "survived the walk — layout wrong past the group array");
    }
}

void report_tint_hit(const char* shape, const char* detail) noexcept {
    note("TINT-PROBE", detail);
    FW_LOG("[chargen-dump] tint probe HIT (%s): %s", shape, detail);
}

int probe_race_tints(std::uintptr_t base, void* race) noexcept {
    auto* r = reinterpret_cast<std::uint8_t*>(race);
    int hits = 0;
    char d[360];

    for (std::size_t o = 0; o < RACE_SCAN_BYTES && hits < 16; o += 8) {
        // Shape 0 — the object is embedded in the race itself, so the qword
        // at race+o IS a vtable pointer. The first pass missed this: it only
        // ever treated race+o as a pointer TO something.
        void* raw = safe_deref(r + o);
        if (raw && reinterpret_cast<std::uintptr_t>(raw) > base) {
            const auto rva = reinterpret_cast<std::uintptr_t>(raw) - base;
            if (rva == VT_TPL_ENTRY || rva == VT_TPL_MASK ||
                rva == VT_TPL_PALETTE || rva == VT_TPL_TEXSET ||
                rva == VT_ENTRY || rva == VT_MASK_ENTRY ||
                rva == VT_PAL_ENTRY || rva == VT_TEX_ENTRY) {
                std::snprintf(d, sizeof(d),
                              "race+0x%03zX\tembedded\tvtable_rva=0x%llX",
                              o, static_cast<unsigned long long>(rva));
                report_tint_hit("embedded", d);
                ++hits;
                continue;
            }
        }

        void* p1 = raw;
        if (!p1) continue;

        // Shape A — race+o points straight at a template object.
        if (const char* n = tint_class_of(base, p1)) {
            std::snprintf(d, sizeof(d), "race+0x%03zX\tdirect\tobj=%p\t%s",
                          o, p1, n);
            report_tint_hit("direct", d);
            ++hits;
            continue;
        }

        // Shape B — race+o is an array's data pointer. Covers both an array
        // of pointers (first element is the object) and an array of objects
        // laid out inline (the data pointer IS the first object), which the
        // first pass only half-checked.
        void* first = safe_deref(p1);
        if (const char* n = tint_class_of(base, first)) {
            std::snprintf(d, sizeof(d),
                          "race+0x%03zX\tarray-of-ptr\tdata=%p\telem0=%p\t%s",
                          o, p1, first, n);
            report_tint_hit("array-of-ptr", d);
            ++hits;
            continue;
        }

        auto* s = reinterpret_cast<std::uint8_t*>(p1);
        for (std::size_t k = 0; k < STRUCT_SCAN_BYTES && hits < 16; k += 8) {
            void* p2 = safe_deref(s + k);
            if (!p2) continue;

            // Shape C1 — the intermediate struct holds an array of objects,
            // so p2 is the first object. Missing from the first pass.
            if (const char* n = tint_class_of(base, p2)) {
                std::snprintf(d, sizeof(d),
                              "race+0x%03zX\tstruct+0x%03zX\tarray-of-obj"
                              "\tobj0=%p\t%s", o, k, p2, n);
                report_tint_hit("array-of-obj", d);
                ++hits;
                break;
            }

            // Shape C2 — array of pointers behind the intermediate struct.
            void* e = safe_deref(p2);
            if (const char* n = tint_class_of(base, e)) {
                std::uint32_t maybe_size = 0;
                __try {
                    maybe_size = *reinterpret_cast<std::uint32_t*>(s + k + 0x10);
                } __except (EXCEPTION_EXECUTE_HANDLER) {}
                std::snprintf(d, sizeof(d),
                              "race+0x%03zX\tstruct+0x%03zX\tdata=%p\telem0=%p"
                              "\tsize?=%u\t%s", o, k, p2, e, maybe_size, n);
                report_tint_hit("struct-array", d);
                ++hits;
                break;
            }

            // Shape D — one level deeper. FO4 splits chargen data by sex, so
            // race -> chargen block -> per-sex block -> array is a realistic
            // depth and the first pass stopped one short of it.
            auto* t = reinterpret_cast<std::uint8_t*>(p2);
            for (std::size_t j = 0; j < DEEP_SCAN_BYTES && hits < 16; j += 8) {
                void* p3 = safe_deref(t + j);
                if (!p3) continue;
                const char* n3 = tint_class_of(base, p3);
                if (!n3) n3 = tint_class_of(base, safe_deref(p3));
                if (n3) {
                    std::snprintf(d, sizeof(d),
                                  "race+0x%03zX\t+0x%03zX\t+0x%03zX\tp=%p\t%s",
                                  o, k, j, p3, n3);
                    report_tint_hit("deep", d);
                    ++hits;
                    break;
                }
            }
            if (hits) break;
        }
    }
    return hits;
}

// The templates may simply not exist yet: nothing in a loaded save needs
// them, and the creation menu is the only thing that does. So keep trying
// while the session runs instead of concluding "absent" from one look at a
// moment when absence is the expected state.
void maybe_probe_tints(std::uintptr_t base) noexcept {
    static std::atomic<int> s_tries{0};
    static std::atomic<bool> s_done{false};
    static DWORD s_last = 0;
    if (s_done.load(std::memory_order_relaxed)) return;
    if (!g_human_race) return;

    // The scan is not cheap (up to ~1 M guarded reads). Every 5 s is plenty
    // to catch a menu being opened.
    const DWORD now = GetTickCount();
    if (s_last && now - s_last < 5000) return;
    s_last = now;

    const int t = s_tries.fetch_add(1, std::memory_order_relaxed);
    if (t == 0) dump_tint_chain(base, g_human_race);
    if (t >= TINT_PROBE_TRIES) {
        if (t == TINT_PROBE_TRIES) {
            FW_WRN("[chargen-dump] tint probe: gave up after %d attempts — "
                   "the templates were never reachable from the race. They "
                   "are held somewhere else entirely.", TINT_PROBE_TRIES);
            note("TINT-PROBE", "gave-up");
        }
        return;
    }

    const int hits = probe_race_tints(base, g_human_race);
    if (hits > 0) {
        s_done.store(true, std::memory_order_relaxed);
        FW_LOG("[chargen-dump] tint probe: %d hit(s) on attempt %d — layout "
               "recorded, probe disarmed", hits, t);
    } else if (t == 0) {
        FW_LOG("[chargen-dump] tint probe: nothing yet (attempt 1 of %d). "
               "If they are allocated lazily, opening the character-creation "
               "menu is what will make them appear.", TINT_PROBE_TRIES);
    }
}

// --- detours ---------------------------------------------------------------

// Blocker #1 observation. Read-only: log and chain. The point is the FIRST
// argument — the appearance context whose identity static RE left open — so
// dump enough of it to recognise what it is: the TESNPC it carries at +0x60
// (with that NPC's form id), the +0x78 field the function insists on, and
// the second argument's form id and type.
void __fastcall detour_head_build(void* a1, void* a2) {
    if (g_on.load(std::memory_order_relaxed)) {
        __try {
            auto* c = reinterpret_cast<std::uint8_t*>(a1);
            void* npc  = a1 ? *reinterpret_cast<void**>(c + 0x60) : nullptr;
            void* f78  = a1 ? *reinterpret_cast<void**>(c + 0x78) : nullptr;
            char det[512];
            std::snprintf(det, sizeof(det),
                          "ctx=%p\tctx_vt_rva=0x%llX\tnpc=%p\tnpc_fid=0x%08X"
                          "\tctx+0x78=%p\tref=%p\tref_fid=0x%08X\tref_type=%u"
                          "\tcaller=+0x%llX",
                          a1,
                          static_cast<unsigned long long>(
                              a1 ? (*reinterpret_cast<std::uintptr_t*>(c)
                                    - g_module) : 0),
                          npc, npc ? form_id(npc) : 0, f78,
                          a2, a2 ? form_id(a2) : 0,
                          a2 ? *(reinterpret_cast<std::uint8_t*>(a2)
                                 + FORM_TYPE_OFF) : 0,
                          static_cast<unsigned long long>(
                              reinterpret_cast<std::uintptr_t>(
                                  _ReturnAddress()) - g_module));
            // What a SUCCESSFUL rebuild looks like. The builder's own gate is
            // ctx+0x60 && ctx+0x78, and +0x78 is filled only via vtable slot
            // 9. Log both, plus ctx+0x84, plus the colour form actually
            // sitting on the NPC at the moment the builder runs — if that is
            // our form and the hair still comes out stock, the write target is
            // wrong and the trigger is innocent.
            void* colour = nullptr;
            if (npc) {
                void* hd = *reinterpret_cast<void**>(
                    reinterpret_cast<std::uint8_t*>(npc) + 0x248);
                if (hd) colour = *reinterpret_cast<void**>(hd);
            }
            const int w2 = static_cast<int>(std::strlen(det));
            std::snprintf(det + w2, sizeof(det) - w2,
                          "	ctx+0x84=0x%08X	npc_colour=%p	colour_fid=0x%08X",
                          *reinterpret_cast<std::uint32_t*>(c + 0x84),
                          colour, colour ? form_id(colour) : 0);
            note("HEAD-BUILD", det);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    if (g_orig_head_build) g_orig_head_build(a1, a2);
}

// The chargen menu's deferred appearance update. a3/a4 are the old and new
// head part in the observed call site; the payload is tagged 0x75.
void* __fastcall detour_appearance_task(void* a1, void* a2, void* a3,
                                        void* a4) {
    if (g_on.load(std::memory_order_relaxed)) {
        __try {
            char det[512];
            std::snprintf(det, sizeof(det),
                          "a1=%p\ta2=%p\ta3=%p\ta3_fid=0x%08X\ta4=%p"
                          "\ta4_fid=0x%08X\ttid=%lu",
                          a1, a2, a3, a3 ? form_id(a3) : 0,
                          a4, a4 ? form_id(a4) : 0,
                          static_cast<unsigned long>(GetCurrentThreadId()));
            // a2 is a stack address that varies per thread — a local context
            // that cannot be synthesised from a disassembly. Window over it
            // so its shape can be read offline instead of guessed, and take
            // the caller RIP while we are here.
            int w = static_cast<int>(std::strlen(det));
            w += std::snprintf(det + w, sizeof(det) - w,
                               "\tcaller=+0x%llX\ta2raw=",
                               static_cast<unsigned long long>(
                                   reinterpret_cast<std::uintptr_t>(
                                       _ReturnAddress()) - g_module));
            for (std::size_t o = 0; o < 0x30 && w > 0 &&
                                    w < static_cast<int>(sizeof(det)) - 24;
                 o += 8) {
                std::uint64_t v = 0;
                __try {
                    v = *reinterpret_cast<std::uint64_t*>(
                        reinterpret_cast<std::uint8_t*>(a2) + o);
                } __except (EXCEPTION_EXECUTE_HANDLER) {}
                w += std::snprintf(det + w, sizeof(det) - w, "%02zX:%016llX ",
                                   o, static_cast<unsigned long long>(v));
            }
            note("APPR-TASK", det);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    return g_orig_appr_task ? g_orig_appr_task(a1, a2, a3, a4) : nullptr;
}

// One detour catches every slider, stepper, preset and colour pick the menu
// performs — the callback id says which, the argument array says with what.
void __fastcall detour_looksmenu(void* menu, void* params) {
    if (g_on.load(std::memory_order_relaxed) && params) {
        __try {
            auto* p = reinterpret_cast<std::uint8_t*>(params);
            const std::int32_t id = *reinterpret_cast<std::int32_t*>(p + 0x30);
            const std::uint32_t argc =
                *reinterpret_cast<std::uint32_t*>(p + 0x28);
            auto* args = *reinterpret_cast<std::uint8_t**>(p + 0x20);
            char det[768];
            int w = std::snprintf(det, sizeof(det), "id=%d\targc=%u", id, argc);
            if (args) {
                const std::uint32_t lim = argc > 8 ? 8 : argc;
                for (std::uint32_t i = 0; i < lim && w > 0
                         && w < static_cast<int>(sizeof(det)) - 48; ++i) {
                    auto* a = args + 0x20 * i;
                    const std::uint32_t ty =
                        *reinterpret_cast<std::uint32_t*>(a + 0x08);
                    const auto* pay = a + 0x10;
                    // 2 = bool, 4 = uint, 5 = double; anything else is dumped
                    // raw so nothing is silently lost.
                    if (ty == 5) {
                        w += std::snprintf(det + w, sizeof(det) - w,
                                           "\targ%u=%.4f(d)", i,
                                           *reinterpret_cast<const double*>(pay));
                    } else if (ty == 2) {
                        w += std::snprintf(det + w, sizeof(det) - w,
                                           "\targ%u=%u(b)", i,
                                           *reinterpret_cast<const std::uint8_t*>(pay) ? 1u : 0u);
                    } else {
                        w += std::snprintf(det + w, sizeof(det) - w,
                                           "\targ%u=%u(t%u)", i,
                                           *reinterpret_cast<const std::uint32_t*>(pay), ty);
                    }
                }
            }
            note("ui", det);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    if (g_orig_looksmenu) g_orig_looksmenu(menu, params);
}

void __fastcall detour_setmorph(void* npc, std::uint32_t key, float value) {
    if (g_on.load(std::memory_order_relaxed)) {
        char det[192];
        std::snprintf(det, sizeof(det), "npc=0x%08X\tkey=%u\tvalue=%.5f%s",
                      form_id(npc), key, value,
                      value == 0.0f ? "\t(erase)" : "");
        note("morph", det);
    }
    if (g_orig_setmorph) g_orig_setmorph(npc, key, value);
}

// --- TESNPC appearance-field discovery ------------------------------------
// The recipe (CHARGEN_PLAN §12) has to be READ off an NPC and WRITTEN back to
// one. Both need to know where appearance lives inside TESNPC — and that
// layout has not been established for this build.
//
// Same method that settled the tint container, the head-build context and the
// hair-colour representation: do not guess the offsets, watch the engine
// write them. Snapshot a window of the NPC before an apply, let the engine
// run, snapshot after, and report only what moved. The changed offsets ARE
// the layout.
//
// Read-only with respect to the engine: this adds no calls, only two copies
// and a compare.
constexpr std::size_t NPC_DIFF_WINDOW = 0x400;   // 1 KB covers the record

void diff_npc(const char* tag, const void* npc,
              const std::uint8_t* before) noexcept {
    if (!npc || !before) return;
    std::uint8_t after[NPC_DIFF_WINDOW];
    __try {
        std::memcpy(after, npc, NPC_DIFF_WINDOW);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return; }

    char det[1100];
    int w = std::snprintf(det, sizeof(det), "tag=%s	npc=0x%08X	delta=",
                          tag, form_id(npc));
    int changed = 0;
    for (std::size_t o = 0; o < NPC_DIFF_WINDOW && w > 0 &&
                            w < static_cast<int>(sizeof(det)) - 48; o += 8) {
        std::uint64_t b = 0, a = 0;
        std::memcpy(&b, before + o, 8);
        std::memcpy(&a, after + o, 8);
        if (b == a) continue;
        ++changed;
        w += std::snprintf(det + w, sizeof(det) - w,
                           "+%03zX:%llX->%llX ", o,
                           static_cast<unsigned long long>(b),
                           static_cast<unsigned long long>(a));
    }
    if (changed == 0) {
        std::snprintf(det + w, sizeof(det) - w, "(none in 0x%zX)",
                      NPC_DIFF_WINDOW);
    }
    note("NPC-DIFF", det);
}

// The first diff came back empty: applying a hair colour changed nothing in
// the NPC's own 0x400 bytes, yet a respawn later rendered that colour — so it
// is stored behind a pointer, in a sub-object. Rather than widen the window
// blindly, hunt for the value we just handed the engine: wherever the applied
// form pointer ends up IS the field.
//
// Two levels, both bounded and guarded, same shape as the tint probe that
// located the race tint container.
void find_value_in_npc(const char* tag, const void* npc,
                       const void* needle) noexcept {
    if (!npc || !needle) return;
    const auto want = reinterpret_cast<std::uintptr_t>(needle);
    char det[900];
    int  w = std::snprintf(det, sizeof(det), "tag=%s	npc=0x%08X	value=%p	at=",
                           tag, form_id(npc), needle);
    int hits = 0;

    for (std::size_t o = 0; o < NPC_DIFF_WINDOW && w > 0 &&
                            w < static_cast<int>(sizeof(det)) - 40; o += 8) {
        std::uintptr_t v = 0;
        __try {
            v = *reinterpret_cast<const std::uintptr_t*>(
                reinterpret_cast<const std::uint8_t*>(npc) + o);
        } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }

        if (v == want) {
            w += std::snprintf(det + w, sizeof(det) - w, "npc+0x%03zX ", o);
            ++hits;
            continue;
        }
        // One level in: the sub-object the record hangs the data off.
        if (v < 0x10000 || v > 0x00007FFFFFFFFFFFULL || (v & 7)) continue;
        for (std::size_t k = 0; k < 0x200 && w > 0 &&
                                w < static_cast<int>(sizeof(det)) - 44; k += 8) {
            std::uintptr_t v2 = 0;
            __try {
                v2 = *reinterpret_cast<const std::uintptr_t*>(
                    reinterpret_cast<const std::uint8_t*>(v) + k);
            } __except (EXCEPTION_EXECUTE_HANDLER) { break; }
            if (v2 == want) {
                w += std::snprintf(det + w, sizeof(det) - w,
                                   "npc+0x%03zX->+0x%03zX ", o, k);
                ++hits;
            }
        }
    }
    if (hits == 0) {
        std::snprintf(det + w, sizeof(det) - w, "NOT-FOUND(2 levels)");
    }
    note("NPC-FIND", det);

    // The head-part hunt landed on npc+0x2D0: the applied part is element 0
    // of whatever that points at. Dump the surrounding region so the array
    // triple (data / capacity / size) can be read off the bytes, then walk it
    // — with every element guarded and only stringified once its form type
    // says head part.
    {
        char d5[900];
        int  w5 = std::snprintf(d5, sizeof(d5), "npc=0x%08X	region=",
                                form_id(npc));
        for (std::size_t o = 0x2C0; o < 0x300 && w5 > 0 &&
                                    w5 < static_cast<int>(sizeof(d5)) - 24;
             o += 8) {
            std::uint64_t v = 0;
            __try {
                v = *reinterpret_cast<const std::uint64_t*>(
                    reinterpret_cast<const std::uint8_t*>(npc) + o);
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            w5 += std::snprintf(d5 + w5, sizeof(d5) - w5, "%03zX:%llX ", o,
                                static_cast<unsigned long long>(v));
        }
        note("NPC-HDPTREGION", d5);

        void*         hp_data = nullptr;
        __try {
            hp_data = *reinterpret_cast<void* const*>(
                reinterpret_cast<const std::uint8_t*>(npc) + 0x2D0);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        if (hp_data) {
            char d6[900];
            int  w6 = std::snprintf(d6, sizeof(d6), "npc=0x%08X	data=%p	",
                                    form_id(npc), hp_data);
            for (std::uint32_t i = 0; i < 16 && w6 > 0 &&
                                      w6 < static_cast<int>(sizeof(d6)) - 56;
                 ++i) {
                void* e = nullptr;
                __try {
                    e = *reinterpret_cast<void* const*>(
                        reinterpret_cast<std::uint8_t*>(hp_data) + 8u * i);
                } __except (EXCEPTION_EXECUTE_HANDLER) { break; }
                const auto ev = reinterpret_cast<std::uintptr_t>(e);
                if (ev < 0x10000 || ev > 0x00007FFFFFFFFFFFULL || (ev & 7)) {
                    break;   // end of the meaningful run
                }
                auto* eb = reinterpret_cast<std::uint8_t*>(e);
                const std::uint8_t etyp = static_cast<std::uint8_t>(
                    seh_read_u32(eb + FORM_TYPE_OFF) & 0xFF);
                char edid[80] = {};
                if (etyp == FORMTYPE_HDPT) {
                    read_bsfixed(eb + HDPT_EDITORID, edid, sizeof(edid));
                }
                w6 += std::snprintf(d6 + w6, sizeof(d6) - w6,
                                    "[%u]=0x%08X:t%u:%s ", i,
                                    seh_read_u32(eb + FORM_ID_OFF), etyp, edid);
            }
            note("NPC-HDPTARR", d6);
        }
    }

    // The hunt named npc+0x248 as a stable pointer whose target's first field
    // is the applied colour — the shape of TESNPC's head-related sub-object.
    // Dump it: if the rest of the recipe (head-part array, texture set) lives
    // there too, one window gives the whole layout.
    {
        // 2026-08-08 CORRECTED. This used to dump a 0x80-byte window here and
        // then walk two "BSTArray triples" it found at +0x18 and +0x48.
        //
        // The object is 0x18 BYTES. sub_140654DF0 allocates exactly 0x18 and
        // the destructor frees 24. It is three TESForm pointers, all resolved
        // in the Link pass with explicit _RTDynamicCast, and nothing else:
        //
        //   +0x00  BGSColorForm*   hair colour        get sub_140654D80
        //   +0x08  BGSColorForm*   secondary colour   set sub_140654EF0
        //   +0x10  BGSTextureSet*  face texture set   set sub_140654F80
        //
        // Everything the old window printed past +0x18 was heap garbage, and
        // the 11-entry and 5-entry "arrays" in the 2026-08-07 log do not exist.
        // The "5 unidentified floats in the head sub-object" once noted as a
        // lead for body build came from the same bad read; that lead is void.
        //
        // Note the getter's fallback, which the editor will need: when +0x00 is
        // null the engine falls back to the race default at CharGenData+0x28,
        // so a null here does NOT mean "no hair colour".
        void* sub = safe_deref(
            reinterpret_cast<const std::uint8_t*>(npc) + 0x248);
        if (sub) {
            auto* s = reinterpret_cast<std::uint8_t*>(sub);
            void* hair  = safe_deref(s + 0x00);
            void* second= safe_deref(s + 0x08);
            void* texset= safe_deref(s + 0x10);
            char hname[128] = {}, sname[128] = {};
            if (hair)   read_bsfixed(reinterpret_cast<std::uint8_t*>(hair)
                                     + CLFM_NAME, hname, sizeof(hname));
            if (second) read_bsfixed(reinterpret_cast<std::uint8_t*>(second)
                                     + CLFM_NAME, sname, sizeof(sname));
            char d2[700];
            std::snprintf(d2, sizeof(d2),
                          "npc=0x%08X	sub=%p	hair=0x%08X(%s)"
                          "	second=0x%08X(%s)	texset=0x%08X",
                          form_id(npc), sub,
                          hair ? form_id(hair) : 0,
                          hname[0] ? hname : "(none)",
                          second ? form_id(second) : 0,
                          sname[0] ? sname : "(none)",
                          texset ? form_id(texset) : 0);
            note("NPC-HEADDATA", d2);
        }
    }
}

bool snapshot_npc(const void* npc, std::uint8_t* out) noexcept {
    if (!npc) return false;
    __try {
        std::memcpy(out, npc, NPC_DIFF_WINDOW);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

void __fastcall detour_addheadpart(void* npc, void* part, bool a, bool b,
                                   bool c) {
    if (g_on.load(std::memory_order_relaxed) && part) {
        __try {
            auto* hp = reinterpret_cast<std::uint8_t*>(part);
            char model[320] = {}, edid[128] = {};
            read_bsfixed(hp + HDPT_MODEL, model, sizeof(model));
            read_bsfixed(hp + HDPT_EDITORID, edid, sizeof(edid));
            const std::uint32_t pnam =
                *reinterpret_cast<std::uint32_t*>(hp + HDPT_PNAM);
            char det[640];
            std::snprintf(det, sizeof(det),
                          "npc=0x%08X\thdpt=0x%08X\ttype=%u(%s)\tedid=%s"
                          "\tmodel=%s", form_id(npc), form_id(part), pnam,
                          pnam < 10 ? kPartType[pnam] : "?", edid, model);
            note("apply-headpart", det);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    std::uint8_t before[NPC_DIFF_WINDOW];
    const bool snapped = g_on.load(std::memory_order_relaxed) &&
                         snapshot_npc(npc, before);
    if (g_orig_addheadpart) g_orig_addheadpart(npc, part, a, b, c);
    if (snapped) {
        diff_npc("headpart", npc, before);
        find_value_in_npc("headpart", npc, part);
        // BYTE-granular before/after over the head-part region. The recipe
        // reader currently walks TESNPC+0x2D0 to the first null and OVERRUNS
        // — it returned 65 parts including female ones for a male player. The
        // count field was never located; the region dump showed the low byte
        // at +0x2E8 equal to 0x0D = 13, which matches the real entry count
        // exactly. This proves or kills that: applying a part must move the
        // count by one, and only one byte should move.
        __try {
            char d[900];
            int  w = std::snprintf(d, sizeof(d), "npc=0x%08X	moved=",
                                   form_id(npc));
            int moved = 0;
            for (std::size_t o = 0x2C0; o < 0x300 && w > 0 &&
                                        w < static_cast<int>(sizeof(d)) - 32;
                 ++o) {
                const std::uint8_t b = before[o];
                const std::uint8_t a = *(reinterpret_cast<std::uint8_t*>(npc) + o);
                if (b == a) continue;
                ++moved;
                w += std::snprintf(d + w, sizeof(d) - w, "+%03zX:%u->%u ",
                                   o, b, a);
            }
            if (moved == 0) {
                std::snprintf(d + w, sizeof(d) - w, "(nothing in 2C0..300)");
            }
            note("HDPT-COUNT", d);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}

void __fastcall detour_haircolor(void* npc, void* colour_form) {
    if (g_on.load(std::memory_order_relaxed)) {
        // The form id alone is not enough. Hair colour is a hard requirement
        // and last night proved the RGB cannot be guessed out of the
        // material, so capture it at the SOURCE: the name the menu shows
        // plus a raw window over the colour form, which is where the value
        // has to live. Finding the field offline beats another live guess.
        char name[128] = {};
        read_bsfixed(reinterpret_cast<std::uint8_t*>(colour_form) + 0x28,
                     name, sizeof(name));
        char det[640];
        int w = std::snprintf(det, sizeof(det),
                              "npc=0x%08X\tcolorform=0x%08X\tname=%s\traw=",
                              form_id(npc), form_id(colour_form), name);
        for (std::size_t o = 0x18; o < 0x50 && w > 0 &&
                                   w < static_cast<int>(sizeof(det)) - 16;
             o += 4) {
            std::uint32_t v = 0;
            __try {
                v = *reinterpret_cast<std::uint32_t*>(
                    reinterpret_cast<std::uint8_t*>(colour_form) + o);
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            w += std::snprintf(det + w, sizeof(det) - w, "%02zX:%08X ", o, v);
        }
        note("apply-haircolor", det);
    }
    std::uint8_t before[NPC_DIFF_WINDOW];
    const bool snapped = g_on.load(std::memory_order_relaxed) &&
                         snapshot_npc(npc, before);
    if (g_orig_haircolor) g_orig_haircolor(npc, colour_form);
    if (snapped) {
        diff_npc("haircolor", npc, before);
        find_value_in_npc("haircolor", npc, colour_form);
    }
}

// The hair-colour REFRESH path. Unlike eye colour, a hair change posts no
// task: it raises a dirty byte at menu+0x518, and the chargen update
// consumes it by calling this with the TESNPC and two stack callbacks
// (sub_140D0BE20 / sub_140D0BD90 at the observed site). Nine arguments and
// two callbacks are not something to synthesise from a disassembly, so log
// what really arrives and who called it.
void* __fastcall detour_refresh(void* a1, void* a2, void* a3, void* a4,
                                std::uint64_t a5, std::uint64_t a6,
                                std::uint64_t a7, std::uint64_t a8,
                                std::uint64_t a9) {
    if (g_on.load(std::memory_order_relaxed)) {
        __try {
            char det[512];
            std::snprintf(det, sizeof(det),
                          "a1=%p\ta2=%p\ta2_fid=0x%08X\ta2_type=%u\ta3=%p"
                          "\ta4=%p\tcaller=+0x%llX\ttid=%lu",
                          a1, a2, a2 ? form_id(a2) : 0,
                          a2 ? *(reinterpret_cast<std::uint8_t*>(a2)
                                 + FORM_TYPE_OFF) : 0,
                          a3, a4,
                          static_cast<unsigned long long>(
                              reinterpret_cast<std::uintptr_t>(
                                  _ReturnAddress()) - g_module),
                          static_cast<unsigned long>(GetCurrentThreadId()));
            note("REFRESH", det);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    return g_orig_refresh
               ? g_orig_refresh(a1, a2, a3, a4, a5, a6, a7, a8, a9)
               : nullptr;
}

// A head rebuild is QUEUED, not called. This fires once per queued rebuild;
// the caller RIP is the point of the whole hook, because it names whatever
// actually triggers a rebuild in ordinary play — which is the lever the
// donor pipeline needs, and the one thing static reading could not settle.
void* __fastcall detour_queued_head(void* self, void* a2, void* a3,
                                    std::uint32_t a4, std::uint64_t a5) {
    void* r = g_orig_queued_head
                  ? g_orig_queued_head(self, a2, a3, a4, a5)
                  : nullptr;
    if (g_on.load(std::memory_order_relaxed)) {
        __try {
            char det[256];
            std::snprintf(det, sizeof(det),
                          // The ctor returns a small integer (observed 4/5/6),
                          // not the QueuedHead — so report `self`, which IS
                          // the object, and keep the return value separate
                          // instead of conflating the two.
                          "qh=%p\tret=%llu\ta2=%p\tcaller=+0x%llX\ttid=%lu",
                          self,
                          static_cast<unsigned long long>(
                              reinterpret_cast<std::uintptr_t>(r)),
                          a2,
                          static_cast<unsigned long long>(
                              reinterpret_cast<std::uintptr_t>(
                                  _ReturnAddress()) - g_module),
                          static_cast<unsigned long>(GetCurrentThreadId()));
            note("QUEUED-HEAD", det);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    return r;
}

// --- catalogue -------------------------------------------------------------

// Walk one TESDataHandler array and hand each form to `fn`.
template <typename F>
std::uint32_t walk_forms(std::uintptr_t base, std::uint8_t type, F fn) noexcept {
    std::uint32_t seen = 0;
    __try {
        auto* dh = *reinterpret_cast<std::uint8_t**>(base + DATAHANDLER_RVA);
        if (!dh) return 0;
        auto* arr = dh + DH_ARRAYS_OFF + DH_ARRAY_STRIDE * type;
        auto** data = *reinterpret_cast<void***>(arr);
        const std::uint32_t size = *reinterpret_cast<std::uint32_t*>(arr + 0x10);
        if (!data || size == 0 || size > 200000) return 0;
        for (std::uint32_t i = 0; i < size; ++i) {
            void* form = data[i];
            if (!form) continue;
            fn(form);
            ++seen;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return seen;
}

}  // namespace

void maybe_dump_catalogue(std::uintptr_t module_base) noexcept {
    if (!g_on.load(std::memory_order_relaxed)) return;
    if (!module_base) return;
    // The head-part catalogue is one-shot, but the tint probe is not: it has
    // to keep looking, because the templates may only be built when the
    // creation menu opens. So a finished catalogue falls through to it
    // instead of returning.
    if (g_catalogue_done.load(std::memory_order_relaxed)) {
        maybe_probe_tints(module_base);
        return;
    }

    // One-shot probe of the raw array triple, before any interpretation.
    //
    // The first capture session produced ZERO catalogue records and said
    // nothing about why — the walk returns 0 both when the data handler is
    // not populated yet (normal, retry) and when the offsets are wrong
    // (fatal, retry forever). Those two look identical from the outside, and
    // telling them apart cost a whole session. So the first few attempts now
    // print what was actually read: if `dh` is null the handler is not up
    // yet, if `size` is 0 the arrays are empty, and if `size` is nonsense the
    // layout constants below are wrong.
    {
        static std::atomic<int> s_probes{0};
        const int p = s_probes.fetch_add(1, std::memory_order_relaxed);
        if (p < 3) {
            void*         dh   = nullptr;
            void**        data = nullptr;
            std::uint32_t cap = 0, size = 0;
            __try {
                dh = *reinterpret_cast<void**>(module_base + DATAHANDLER_RVA);
                if (dh) {
                    auto* arr = reinterpret_cast<std::uint8_t*>(dh) +
                                DH_ARRAYS_OFF + DH_ARRAY_STRIDE * FORMTYPE_HDPT;
                    data = *reinterpret_cast<void***>(arr);
                    cap  = *reinterpret_cast<std::uint32_t*>(arr + 0x08);
                    size = *reinterpret_cast<std::uint32_t*>(arr + 0x10);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            FW_LOG("[chargen-dump] probe %d: handler=%p hdpt{data=%p cap=%u "
                   "size=%u} (arrays@+0x%X stride 0x%X, type %u)",
                   p, dh, static_cast<void*>(data), cap, size,
                   static_cast<unsigned>(DH_ARRAYS_OFF),
                   static_cast<unsigned>(DH_ARRAY_STRIDE),
                   static_cast<unsigned>(FORMTYPE_HDPT));
        }
    }

    // Head parts: the catalogue that matters. Everything the game can put on
    // a face, with the mesh that draws it and the morph sets that deform it.
    const std::uint32_t n_hdpt = walk_forms(module_base, FORMTYPE_HDPT,
        [](void* form) {
            auto* hp = reinterpret_cast<std::uint8_t*>(form);
            char model[320] = {}, edid[128] = {}, full[128] = {};
            read_bsfixed(hp + HDPT_MODEL,    model, sizeof(model));
            read_bsfixed(hp + HDPT_EDITORID, edid,  sizeof(edid));
            read_bsfixed(hp + HDPT_FULLNAME, full,  sizeof(full));
            std::uint32_t pnam = 0, extra = 0;
            std::uint8_t flags = 0;
            __try {
                pnam  = *reinterpret_cast<std::uint32_t*>(hp + HDPT_PNAM);
                flags = *(hp + HDPT_FLAGS);
                extra = *reinterpret_cast<std::uint32_t*>(hp + HDPT_EXTRA_SIZE);
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            char morphs[3][320] = {};
            for (int m = 0; m < 3; ++m) {
                read_bsfixed(hp + HDPT_MORPH0 + HDPT_MORPH_STRIDE * m + 0x08,
                             morphs[m], sizeof(morphs[m]));
            }
            char det[1100];
            std::snprintf(det, sizeof(det),
                "id=0x%08X\ttype=%u(%s)\tflags=0x%02X\textra=%u\tedid=%s"
                "\tname=%s\tmodel=%s\tmorph0=%s\tmorph1=%s\tmorph2=%s",
                form_id(form), pnam, pnam < 10 ? kPartType[pnam] : "?",
                flags, extra, edid, full, model,
                morphs[0], morphs[1], morphs[2]);
            note("HDPT", det);
        });

    if (n_hdpt == 0) return;   // data handler not populated yet — try again

    const std::uint32_t n_race = walk_forms(module_base, FORMTYPE_RACE,
        [](void* form) {
            auto* r = reinterpret_cast<std::uint8_t*>(form);
            char edid[128] = {}, full[160] = {};
            char skel_m[320] = {}, skel_f[320] = {};
            // 2026-08-08 FIXED. Editor ids are not at a uniform offset — they
            // are a TESForm virtual (slot 58, +0x1D0), and the base
            // implementation discards the value, so only 18 of 144 form classes
            // keep one. BGSHeadPart keeps its at +0x170, which is why reading
            // that offset worked for HDPT and produced nothing but handled AVs
            // for everything else. TESRace keeps its at +0x3A0, and its display
            // name is a TESFullName component at +0x28.
            read_bsfixed(r + RACE_EDITORID, edid, sizeof(edid));
            read_bsfixed(r + RACE_FULLNAME, full, sizeof(full));
            // race+0xC0 + 0x30*sex = skeleton TESModel, path at +0x08
            read_bsfixed(r + 0xC0 + 0x08,        skel_m, sizeof(skel_m));
            read_bsfixed(r + 0xC0 + 0x30 + 0x08, skel_f, sizeof(skel_f));
            // DATA flags; bit 0 is Playable, which is what a race picker must
            // filter on. Reached in the engine as TESRace vtable slot 29, whose
            // whole body is `return *(BYTE*)(this + 0x1A0) & 1`.
            const std::uint32_t dflags = seh_read_u32(r + RACE_DATA_FLAGS);
            // Does this race carry any tint data at all? A race with no TTGP
            // subrecords has a null CharGenData block or a null container, and
            // the editor must not offer it tint categories.
            int tint_sexes = 0;
            for (int sx = 0; sx < 2; ++sx) {
                void* slot = safe_deref(r + RACE_TINT_SLOT + 8u * sx);
                if (slot && safe_deref(slot)) ++tint_sexes;
            }
            char det[1100];
            std::snprintf(det, sizeof(det),
                          "id=0x%08X\tedid=%s\tname=%s\tdata_flags=0x%08X"
                          "\tplayable=%d\ttint_sexes=%d\tskel_m=%s\tskel_f=%s",
                          form_id(form), edid, full, dflags,
                          (dflags & RACE_FLAG_PLAYABLE) ? 1 : 0,
                          tint_sexes, skel_m, skel_f);
            note("RACE", det);
            if (form_id(form) == HUMAN_RACE_FID) g_human_race = form;
        });

    const std::uint32_t n_clfm = walk_forms(module_base, FORMTYPE_CLFM,
        [](void* form) {
            auto* c = reinterpret_cast<std::uint8_t*>(form);
            char full[128] = {};
            // +0x28 is the display name — proven, it produced all 166 names.
            // +0x170 is NOT the editor id on this form: reading it is what
            // fills the log with handled AVs inside sub_14167C070 (that
            // offset is BGSHeadPart's). Dropped; the display name is what
            // the menu shows anyway.
            read_bsfixed(c + 0x28, full, sizeof(full));
            // Live capture showed hair colour is NOT an RGB: the value that
            // changes per colour is a single float at +0x30 (Auburn 0.331,
            // Deep Red 0.550, Golden Blond 0.924) — a remap index into a
            // gradient the shader samples. That is why copying colour fields
            // out of the material could never work. Dump a wide raw window
            // over every colour form so the rest of the layout (and whether
            // an RGB exists at all) is settled offline, from all 166 at once,
            // with no extra play session.
            char det[900];
            int w = std::snprintf(det, sizeof(det),
                                  "id=0x%08X\tname=%s\tremap=%.6f\traw=",
                                  form_id(form), full,
                                  seh_read_f32(c + 0x30));
            for (std::size_t o = 0x00; o < 0x80 && w > 0 &&
                                       w < static_cast<int>(sizeof(det)) - 16;
                 o += 4) {
                w += std::snprintf(det + w, sizeof(det) - w, "%02zX:%08X ",
                                   o, seh_read_u32(c + o));
            }
            note("CLFM", det);
        });

    // Face tints. The race walk above is what located the human race.
    if (!g_human_race) {
        FW_WRN("[chargen-dump] tint probe disabled: HumanRace 0x%08X not "
               "found among %u races", HUMAN_RACE_FID, n_race);
    }
    maybe_probe_tints(module_base);

    g_catalogue_done.store(true, std::memory_order_relaxed);
    FW_LOG("[chargen-dump] catalogue written: %u head parts, %u races, "
           "%u colour forms", n_hdpt, n_race, n_clfm);
}

bool install(std::uintptr_t module_base) {
    if (!g_on.load(std::memory_order_relaxed)) return true;   // not armed
    if (!module_base) return false;

    g_cstr   = reinterpret_cast<CStrFn>(module_base + BSFIXEDSTR_CSTR_RVA);
    g_module = module_base;   // the detours below turn vtables into RVAs

    // 2026-08-06 — the two resource-loader detours are NOT installed.
    //
    // They looked like the obvious capture points and they cost a failed
    // launch: those functions run on the asynchronous streaming threads from
    // the very first moments of boot, thousands of times, and a detour there
    // is the highest-risk hook in this whole project. Any mistake in the
    // signature corrupts the stack instantly, and there is no gentle failure
    // mode during engine start-up.
    //
    // They are also unnecessary. The form catalogue below already carries the
    // mesh path AND the three morph-file paths for every head part, read
    // straight from the records — which is exactly what those hooks were
    // meant to discover, only complete instead of limited to whatever the
    // session happened to touch. Mesh loads still get captured through the
    // long-standing NIF-loader hook, which has been live for months.
    //
    // The four below only fire from the creation menu itself, on the main
    // thread, while a human clicks. Cheap and safe.
    struct Target {
        const char*      name;
        std::uintptr_t   rva;
        void*            detour;
        void**           orig;
    } targets[] = {
        {"looksmenu",    LOOKSMENU_CALL_RVA, reinterpret_cast<void*>(&detour_looksmenu),   reinterpret_cast<void**>(&g_orig_looksmenu)},
        {"set-morph",    NPC_SETMORPH_RVA,   reinterpret_cast<void*>(&detour_setmorph),    reinterpret_cast<void**>(&g_orig_setmorph)},
        {"add-headpart", ADD_HEADPART_RVA,   reinterpret_cast<void*>(&detour_addheadpart), reinterpret_cast<void**>(&g_orig_addheadpart)},
        {"hair-colour",  SET_HAIRCOLOR_RVA,  reinterpret_cast<void*>(&detour_haircolor),   reinterpret_cast<void**>(&g_orig_haircolor)},
        // Blocker #1 observation. head-build fires on ordinary actor loads,
        // so ONE normal session is enough data; no chargen run required.
        {"head-build",   HEAD_BUILD_RVA,     reinterpret_cast<void*>(&detour_head_build),  reinterpret_cast<void**>(&g_orig_head_build)},
        {"appr-task",    APPEARANCE_TASK_RVA, reinterpret_cast<void*>(&detour_appearance_task), reinterpret_cast<void**>(&g_orig_appr_task)},
        {"refresh",      REFRESH_RVA,        reinterpret_cast<void*>(&detour_refresh),      reinterpret_cast<void**>(&g_orig_refresh)},
        {"queued-head",  QUEUED_HEAD_CTOR_RVA, reinterpret_cast<void*>(&detour_queued_head), reinterpret_cast<void**>(&g_orig_queued_head)},
    };

    int ok = 0;
    for (const auto& t : targets) {
        if (fw::hooks::install(reinterpret_cast<void*>(module_base + t.rva),
                               t.detour, t.orig)) {
            ++ok;
        } else {
            FW_WRN("[chargen-dump] hook FAILED: %s (RVA 0x%llX)", t.name,
                   static_cast<unsigned long long>(t.rva));
        }
    }
    FW_LOG("[chargen-dump] %d/%d capture hooks installed", ok,
           static_cast<int>(sizeof(targets) / sizeof(targets[0])));
    return ok > 0;
}

}  // namespace fw::native::chargen_dump
