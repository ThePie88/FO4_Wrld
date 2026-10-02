// L5 stage 2 (2026-09-27) — the player's inventory, captured in observation.
//
// The plan puts the character in an engine checkpoint the server commands
// and the items that cross the boundary in a server journal. Before either
// can be trusted, the DLL must be able to READ the player's inventory the
// way the save writes it: every stack with its count, its flags and the 24
// extra types a save keeps per stack (mods, condition, charge, name,
// favourite, unique id, quest links...). This module is that reader, and
// nothing else: it never writes to the engine, never sends anything yet,
// and reports a capture as complete only when every read succeeded.
//
// It runs on the main-thread WndProc tick, once a second, and only when the
// scene has settled, no load is in flight, no ContainerMenu or power-armour
// station is open (both create transient stacks) and the list's writer bit
// is clear. The list's read lock is taken for the walk (it is re-entrant
// for readers and the engine's own readers take it), every read is SEH-
// caged, every loop is capped, and every extra node is believed only when
// its vtable is the one the RTTI of the executable gives for its type.
//
// The proof that a capture is the whole inventory comes in two layers: a
// self-check per entry against the engine's own count, and, later in this
// stage, a diff against the inventory sub-record of a commanded checkpoint.

#pragma once

#include <cstddef>
#include <cstdint>

namespace fw::config { struct Settings; }
namespace fw::net { struct PaPieceEntry; }

namespace fw::persist::inventory {

constexpr std::size_t MAX_STACKS      = 1024;
constexpr std::size_t MAX_OIE_RECORDS = 16;
constexpr std::size_t MAX_NAME        = 40;

// One 8-byte ObjectModifier record of a BGSObjectInstanceExtra.
struct ModRecord {
    std::uint32_t mod_form_id;
    std::uint8_t  attach_index;
    std::uint8_t  rank;
    std::uint8_t  flag;
    std::uint8_t  pad;
};

// One inventory stack, as the save would write it. POD.
struct StackRecord {
    std::uint32_t base_id;
    std::uint8_t  form_type;
    std::uint8_t  quest_item;       // sub_14028F070 said so
    std::uint16_t flags;            // raw u16 at stack+0x24
    std::int32_t  count;
    std::uint32_t extra_mask;       // bit i = persisted type i present (see TYPE_ORDER)
    std::uint32_t opaque_types;     // count of extra nodes whose type is not in the persisted set
    std::uint32_t unverified_types; // count of persisted-type nodes whose vtable did not match
    float         health;           // ExtraHealth, NaN when absent
    float         charge;           // ExtraCharge, NaN when absent
    std::uint8_t  favorite;         // ExtraFavorite u8, 0xFF when absent
    std::uint8_t  oie_count;
    std::uint8_t  oie_truncated;
    std::uint8_t  name_is_rename;   // 0x99 header bit 0
    std::uint16_t oie_template;     // OIE+0x20
    std::uint16_t uid;              // ExtraUniqueID u16
    std::uint32_t uid_owner;        // ExtraUniqueID u32
    std::int32_t  text_owner;       // ExtraTextDisplayData i32 (+0x30), 0 when absent
    std::uint32_t text_message;     // form id of the message, 0 when none
    std::uint32_t text_quest;       // form id of the quest, 0 when none
    std::uint32_t enchantment;      // form id, 0 when none
    std::uint32_t mod_rank;
    std::uint16_t extra_count;      // ExtraCount u16 (a world stack's count), 0 when absent
    std::uint16_t pad0;
    ModRecord     oie[MAX_OIE_RECORDS];
    char          name[MAX_NAME];   // the literal name of 0x99, when +0x30 == -2
};

// Why a capture is not complete. Bits.
enum : std::uint32_t {
    REASON_NO_LIST        = 1u << 0,   // player has no list yet: "no list", never "empty"
    REASON_WRITER_HELD    = 1u << 1,   // list writer bit set, pass skipped
    REASON_SEH            = 1u << 2,   // a read faulted
    REASON_CAPS           = 1u << 3,   // entries, stacks or extras beyond the caps
    REASON_COUNT_MISMATCH = 1u << 4,   // sum of stacks != engine count for an entry
    REASON_EXTRAS_UNREAD  = 1u << 5,   // an extra list's writer bit was set
    REASON_STACK_VTABLE   = 1u << 6,   // a stack whose vtable is not Stack's
    REASON_HEALTH_CHECK   = 1u << 7,   // decoded health != engine accessor
};

struct Manifest {
    std::uint32_t seq;            // capture number
    std::uint32_t reasons;        // 0 = complete
    std::uint64_t wall_ms;
    std::uint64_t digest;         // FNV-1a 64 over the canonical records
    std::uint32_t entries;        // entries walked
    std::uint32_t stacks;         // records below (transient ones excluded)
    std::uint32_t transient;      // stacks skipped for bit 5
    std::uint32_t capture_us;     // wall time of the locked walk
    std::uint8_t  in_power_armor; // ExtraPowerArmor present on the player REFR
    std::uint8_t  complete;
    std::uint8_t  pad[2];
    StackRecord   records[MAX_STACKS];
};

// Reads the switch (inventory_capture) once, at install time.
void configure(const fw::config::Settings& cfg);

// Where fw_inventory.json (the last complete capture, rewritten on every
// change) and the checkpoint manifests go: the DLL's own directory.
void set_output_dir(const wchar_t* dir);

// Writes the last capture as JSON to `path`. The records carry the same
// fields tools/fos_inventory.py reads out of a save, for the diff.
bool dump_json(const wchar_t* path);

// The main-thread tick: gates, paces to 1 Hz, captures, logs a summary
// when the digest changes (and every record at debug level).
void tick(std::uintptr_t module_base);

// Capture now, gates permitting (used before a checkpoint and at exit
// later in the stage). Returns true when a capture ran.
bool capture_now(std::uintptr_t module_base, const char* why);

// The last capture, complete or not (seq 0 = never). Main thread only.
const Manifest& last();

// L5 stage 2 — INV_DIGEST. The tick sends the last COMPLETE capture when
// its digest changed, at most every 10 s; this sends it now, whatever the
// cadence, for the two moments that matter to the server: right before a
// commanded save (the checkpoint's digest is what stage 3 will compare
// against) and on the way out. An incomplete capture is never sent. `why`
// is a fw::net::kInvDigestWhy* code. Main thread only.
void send_digest_now(std::uint8_t why);

// L5 stage 2 (2026-09-27) — the instance data of ONE world REFR (a dropped
// item), read from its own extra list (+0x100) with the same walker the
// capture uses on a stack: world count (ExtraCount, 1 when absent),
// condition (ExtraHealth, -1 when absent) and the OMOD list, into the wire
// descriptor the world-spawn announce carries as pieces[0]. `out` is always
// filled (a bare descriptor at worst). Returns false when the list could
// not be read to the end, so the caller can say the descriptor is bare and
// not present a half-read one as the whole truth. Main thread; needs no
// prior capture (resolves the engine functions itself).
bool read_refr_instance(std::uintptr_t module_base, void* refr, fw::net::PaPieceEntry* out);

} // namespace fw::persist::inventory
