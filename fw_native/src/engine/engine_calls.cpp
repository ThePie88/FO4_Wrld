#include "engine_calls.h"

#include <windows.h>
#include <atomic>
#include <cmath>
#include <cstring>

#include "../log.h"
#include "../offsets.h"
#include "../ref_identity.h"

namespace fw::engine {

namespace {

// Function pointer types for the engine natives.
using LookupByFormIDFn = void* (*)(std::uint32_t form_id);
using DisableEnqueueFn = void (*)(void* ref, std::uint8_t fade_out);
using EnableCleanupFn  = void (*)(void* ref);
using EnableApplyFn    = void (*)(void* ref);
// B1.e: BGSInventoryList accessor — takes the BGSInventoryItem* (entry
// pointer inside the list), returns its int count.
using InvItemGetCountFn = int (*)(void* entry);
// B1.j.1: BGSInventoryList materializer + CONT component getter. Re-uses
// the engine's own lazy materialization (sub_140511F10 @ 0x511F10) that
// the engine would otherwise invoke the first time the player interacts
// with the container. Calling it ourselves pre-scan ensures REFR+0xF8
// holds the complete list.
using MaterializeInvListFn = void* (*)(void* refr, void* bgscont);
using GetComponentFn       = void* (*)(void* form, std::uint32_t sig);
// B1.g: engine's real AddItem / RemoveItem. Papyrus ObjectReference.AddItem
// / RemoveItem bottom out here after the functor dispatch. Signatures
// documented in offsets.h.
using EngineAddItemFn    = void (*)(
    void* container_refr, void* item_form, std::uint32_t count,
    std::uint8_t flag, std::uint32_t vm_id, void* vm_state);
using EngineRemoveItemFn = void (*)(
    void* container_refr, void* item_form, std::uint32_t count,
    std::uint8_t flag, void* dest_actor_refr, std::uint8_t flag2,
    std::uint32_t vm_id, void* vm_state);
// B1.k.2: sub_14021E230 — BGSObjectRefHandle → TESObjectREFR* resolver.
// Written as: (out_refr_ptr_ptr, in_handle_ptr) → writes to *out.
using RefHandleResolveFn = void (*)(void** out, void* handle_ptr);
// B1.k.3: sub_1403478E0 — ContainerMenu inventory-entry → TESForm*.
// Takes (form_cache_global_value, entry_ptr) → returns form ptr or null.
using InvEntryToFormFn = void* (*)(void* form_cache, void* entry_ptr);
// B3.b: the engine's LoadGame native. Signature decoded from the
// LoadGame console command (re/console_table_report.txt).
using LoadGameFn       = std::uint8_t (*)(
    void* save_load_mgr, const char* filename,
    int unk_neg1, std::uint32_t flags, int one, int zero);
// Precondition check: "is the save device / profile available?"
using LoadPreconditionFn = std::uint8_t (*)(void* save_dev, int a2, int a3);
// Prep call — opaque from the decomp, always called right before LoadGame.
using LoadPrepFn       = void (*)();

// Z.2: PlaceAtMe Papyrus native. Returns Actor*.
// See offsets.h PLACE_AT_ME_RVA for full arg semantics.
using PlaceAtMeFn = void* (*)(
    void* vm, std::uint32_t stack_id, void** form_pair,
    void* anchor_refr, std::uint32_t count, std::uint64_t persistent);

LookupByFormIDFn g_lookup  = nullptr;
DisableEnqueueFn g_disable = nullptr;
EnableCleanupFn  g_enable_cleanup = nullptr;
EnableApplyFn    g_enable_apply   = nullptr;
InvItemGetCountFn g_inv_item_count = nullptr;
MaterializeInvListFn g_materialize_inv = nullptr;
GetComponentFn       g_get_component  = nullptr;
EngineAddItemFn      g_engine_add_item    = nullptr;
EngineRemoveItemFn   g_engine_remove_item = nullptr;
RefHandleResolveFn   g_refhandle_resolve  = nullptr;
InvEntryToFormFn     g_inv_entry_to_form  = nullptr;
// B1.k.3: form-cache global slot. Value at this address is the "form cache"
// singleton pointer that sub_1403478E0 needs as its first arg.
void**               g_form_cache_slot    = nullptr;
LoadGameFn       g_load_game      = nullptr;
LoadPreconditionFn g_load_precond = nullptr;
LoadPrepFn       g_load_prep      = nullptr;
// Pointer to the TESSaveLoadManager singleton slot (qword_14329D508).
// We read its contents at call time — the slot is populated during engine
// init, so reading too early gives 0.
void**           g_save_load_mgr_slot = nullptr;
// Pointer to the "save device" singleton slot (qword_1431E5A90).
void**           g_save_dev_slot      = nullptr;
// Pointer to the "load in progress" flag byte (byte_1432D1FEA).
std::uint8_t*    g_load_in_progress   = nullptr;

// Z.2: PlaceAtMe native + player singleton slot.
PlaceAtMeFn      g_place_at_me         = nullptr;
void**           g_player_singleton_slot = nullptr;   // deref → Actor*

std::atomic<bool> g_ready{false};

// SEH-safe pointer read at offset.
template <typename T>
T safe_read(const void* addr, T fallback) noexcept {
    if (!addr) return fallback;
    __try { return *reinterpret_cast<const T*>(addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return fallback; }
}

// SEH-safe pointer write at offset.
template <typename T>
void safe_write(void* addr, T value) noexcept {
    if (!addr) return;
    __try { *reinterpret_cast<T*>(addr) = value; }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

} // namespace

bool init(std::uintptr_t module_base) {
    if (!module_base) {
        FW_ERR("engine: module_base=0 — cannot resolve calls");
        return false;
    }

    // RVAs from re/reference_fo4_offsets.md (validated via IDA).
    // (DisableEnqueue / EnableCleanup / EnableApply RVAs were already
    // used in the Frida JS era as constants — we're re-using them here.)
    constexpr std::uintptr_t DISABLE_ENQUEUE_RVA = 0x005B3EE0;
    constexpr std::uintptr_t ENABLE_CLEANUP_RVA  = 0x005B4430;
    constexpr std::uintptr_t ENABLE_APPLY_RVA    = 0x005B4140;

    g_lookup = reinterpret_cast<LookupByFormIDFn>(
        module_base + offsets::LOOKUP_BY_FORMID_RVA);
    g_disable = reinterpret_cast<DisableEnqueueFn>(
        module_base + DISABLE_ENQUEUE_RVA);
    g_enable_cleanup = reinterpret_cast<EnableCleanupFn>(
        module_base + ENABLE_CLEANUP_RVA);
    g_enable_apply = reinterpret_cast<EnableApplyFn>(
        module_base + ENABLE_APPLY_RVA);
    g_inv_item_count = reinterpret_cast<InvItemGetCountFn>(
        module_base + offsets::INVITEM_GET_COUNT_RVA);

    // B1.j.1: BGSInventoryList materializer + CONT component getter.
    g_materialize_inv = reinterpret_cast<MaterializeInvListFn>(
        module_base + offsets::BGS_INV_LIST_MATERIALIZE_RVA);
    g_get_component = reinterpret_cast<GetComponentFn>(
        module_base + offsets::TESFORM_GET_COMPONENT_RVA);

    // B1.g: engine's real AddItem / RemoveItem (called by the functor path).
    g_engine_add_item = reinterpret_cast<EngineAddItemFn>(
        module_base + offsets::ENGINE_ADD_ITEM_RVA);
    g_engine_remove_item = reinterpret_cast<EngineRemoveItemFn>(
        module_base + offsets::ENGINE_REMOVE_ITEM_RVA);

    // B1.k.2: BGSObjectRefHandle resolver — for ContainerMenu::TransferItem
    // we need to reach the container REFR from `this+1064` (a handle slot).
    g_refhandle_resolve = reinterpret_cast<RefHandleResolveFn>(
        module_base + offsets::REFHANDLE_RESOLVE_RVA);

    // B1.k.3: ContainerMenu inventory-entry → TESForm* decoder. The engine's
    // ContainerMenu keeps 32-byte-per-entry rows; decoding them requires
    // calling sub_1403478E0 with the form-cache global as context.
    g_inv_entry_to_form = reinterpret_cast<InvEntryToFormFn>(
        module_base + offsets::INV_ENTRY_TO_FORM_RVA);
    g_form_cache_slot = reinterpret_cast<void**>(
        module_base + offsets::FORM_CACHE_SINGLETON_RVA);

    // B3.b: LoadGame ingredients.
    g_load_game = reinterpret_cast<LoadGameFn>(
        module_base + offsets::LOAD_GAME_FN_RVA);
    g_load_precond = reinterpret_cast<LoadPreconditionFn>(
        module_base + offsets::LOAD_PRECOND_FN_RVA);
    g_load_prep = reinterpret_cast<LoadPrepFn>(
        module_base + offsets::LOAD_PREP_FN_RVA);
    g_save_load_mgr_slot = reinterpret_cast<void**>(
        module_base + offsets::SAVE_LOAD_MGR_SINGLETON_RVA);
    g_save_dev_slot = reinterpret_cast<void**>(
        module_base + offsets::SAVE_DEV_SINGLETON_RVA);
    g_load_in_progress = reinterpret_cast<std::uint8_t*>(
        module_base + offsets::LOAD_IN_PROGRESS_FLAG_RVA);

    // Z.2: PlaceAtMe native + player singleton slot (for anchor REFR).
    g_place_at_me = reinterpret_cast<PlaceAtMeFn>(
        module_base + offsets::PLACE_AT_ME_RVA);
    g_player_singleton_slot = reinterpret_cast<void**>(
        module_base + offsets::PLAYER_SINGLETON_RVA);

    g_ready.store(true, std::memory_order_release);
    FW_LOG("engine: calls resolved "
           "lookup=%p disable=%p enable_cleanup=%p enable_apply=%p "
           "inv_item_count=%p materialize_inv=%p get_component=%p "
           "add_item=%p remove_item=%p refhandle=%p "
           "inv_entry_to_form=%p form_cache_slot=%p "
           "load_game=%p precond=%p prep=%p "
           "mgr_slot=%p dev_slot=%p flag=%p",
           g_lookup, g_disable, g_enable_cleanup, g_enable_apply,
           g_inv_item_count, g_materialize_inv, g_get_component,
           g_engine_add_item, g_engine_remove_item, g_refhandle_resolve,
           g_inv_entry_to_form, g_form_cache_slot,
           g_load_game, g_load_precond, g_load_prep,
           g_save_load_mgr_slot, g_save_dev_slot, g_load_in_progress);
    return true;
}

void* lookup_by_form_id(std::uint32_t form_id) {
    if (!g_ready.load(std::memory_order_acquire) || !g_lookup) return nullptr;
    void* result = nullptr;
    __try {
        result = g_lookup(form_id);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("engine: SEH in lookup_by_form_id(0x%X)", form_id);
        result = nullptr;
    }
    return result;
}

std::uint32_t read_flags(void* ref) {
    if (!ref) return 0;
    const auto* base = reinterpret_cast<const std::uint8_t*>(ref);
    return safe_read<std::uint32_t>(base + offsets::FLAGS_OFF, 0u);
}

void disable_ref(void* ref, bool fade_out) {
    if (!g_ready.load(std::memory_order_acquire) || !g_disable || !ref) return;
    __try {
        g_disable(ref, fade_out ? 1 : 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("engine: SEH in disable_ref(%p)", ref);
    }
}

void enable_ref(void* ref) {
    if (!g_ready.load(std::memory_order_acquire)) return;
    if (!g_enable_cleanup || !g_enable_apply || !ref) return;
    __try {
        g_enable_cleanup(ref);
        g_enable_apply(ref);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("engine: SEH in enable_ref(%p)", ref);
    }
}

bool set_disabled_validated(
    std::uint32_t form_id,
    std::uint32_t expected_base_id,
    std::uint32_t expected_cell_id,
    bool disabled)
{
    void* ref = lookup_by_form_id(form_id);
    if (!ref) {
        // Common at bootstrap: the form table isn't populated until after
        // the save loads, so WORLD_STATE apply often misses the first pass.
        // Kept at DBG to avoid log spam; retry-after-save-load is B-level.
        FW_DBG("engine: set_disabled_validated lookup_null form=0x%X", form_id);
        return false;
    }

    // Identity check — refuse to apply if the ref resolves to a different
    // logical actor. expected_* = 0 means skip check (degrade path for
    // legacy entries without identity, kept for compat).
    const auto id = fw::read_ref_identity(ref);
    const bool base_mismatch =
        (expected_base_id != 0) && (id.base_id != expected_base_id);
    const bool cell_mismatch =
        (expected_cell_id != 0) && (id.cell_id != expected_cell_id);
    if (base_mismatch || cell_mismatch) {
        FW_WRN("engine: identity mismatch form=0x%X "
               "got=(base=0x%X, cell=0x%X) expected=(base=0x%X, cell=0x%X)",
               form_id,
               id.base_id, id.cell_id,
               expected_base_id, expected_cell_id);
        return false;
    }

    const std::uint32_t flags = read_flags(ref);
    const bool currently_disabled = (flags & offsets::FLAG_DISABLED) != 0;
    if (disabled && !currently_disabled) {
        disable_ref(ref, /*fade_out=*/false);
        FW_LOG("engine: disable form=0x%X (base=0x%X cell=0x%X)",
               form_id, id.base_id, id.cell_id);
        return true;
    }
    if (!disabled && currently_disabled) {
        enable_ref(ref);
        FW_LOG("engine: enable form=0x%X (base=0x%X cell=0x%X)",
               form_id, id.base_id, id.cell_id);
        return true;
    }
    // No transition needed — already in the desired state.
    return false;
}

void write_ghost_pos_rot(
    std::uint32_t form_id,
    float x, float y, float z,
    float rx, float ry, float rz)
{
    if (!g_ready.load(std::memory_order_acquire)) return;
    void* ref = lookup_by_form_id(form_id);
    if (!ref) return;
    auto* base = reinterpret_cast<std::uint8_t*>(ref);
    safe_write<float>(base + offsets::POS_OFF,     x);
    safe_write<float>(base + offsets::POS_OFF + 4, y);
    safe_write<float>(base + offsets::POS_OFF + 8, z);
    safe_write<float>(base + offsets::ROT_OFF,     rx);
    safe_write<float>(base + offsets::ROT_OFF + 4, ry);
    safe_write<float>(base + offsets::ROT_OFF + 8, rz);
}

bool load_game_by_name(const char* save_name) {
    if (!g_ready.load(std::memory_order_acquire)) {
        FW_WRN("engine: load_game_by_name called before engine init");
        return false;
    }
    if (!save_name || !*save_name) {
        FW_WRN("engine: load_game_by_name called with empty save_name");
        return false;
    }
    if (!g_load_game || !g_load_precond || !g_load_prep ||
        !g_save_load_mgr_slot || !g_save_dev_slot || !g_load_in_progress)
    {
        FW_ERR("engine: load_game_by_name missing resolved pointers — "
               "engine::init didn't populate them");
        return false;
    }

    bool ok = false;
    __try {
        // 1) Precondition: save device available?
        void* save_dev = *g_save_dev_slot;
        if (!save_dev) {
            FW_ERR("engine: LoadGame aborted — save_dev singleton is null "
                   "(engine not fully initialized?)");
            return false;
        }
        const std::uint8_t precond = g_load_precond(save_dev, 0, 0);
        if (!precond) {
            FW_ERR("engine: LoadGame aborted — precondition returned 0 "
                   "(save device / profile not ready)");
            return false;
        }

        // 2) Resolve the TESSaveLoadManager singleton.
        void* mgr = *g_save_load_mgr_slot;
        if (!mgr) {
            FW_ERR("engine: LoadGame aborted — save_load_manager singleton "
                   "is null (engine not fully initialized?)");
            return false;
        }

        // 3) Replicate the exec_fn: prep call + flag + LoadGame.
        FW_LOG("engine: load_game_by_name('%s') → invoking prep + LoadGame",
               save_name);
        g_load_prep();
        *g_load_in_progress = 1;

        // flags=0: all four parsed-flag bits clear (default console behavior
        // when the user types "LoadGame <name>" with no extra switches).
        const std::uint8_t rc = g_load_game(
            mgr, save_name, /*unk_neg1=*/-1, /*flags=*/0,
            /*one=*/1, /*zero=*/0);

        if (rc == 0) {
            FW_ERR("engine: LoadGame returned 0 — savefile '%s' not found "
                   "or unreadable. Check the save name (no path, no .fos "
                   "extension).", save_name);
        } else {
            FW_LOG("engine: LoadGame accepted — engine transitioning to load "
                   "screen for '%s'", save_name);
            ok = true;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("engine: SEH in load_game_by_name('%s')", save_name);
        ok = false;
    }
    return ok;
}

bool apply_global_var(std::uint32_t global_form_id, float value) {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (global_form_id == 0) return false;

    void* form = lookup_by_form_id(global_form_id);
    if (!form) {
        FW_DBG("engine: apply_global_var lookup_null form=0x%X", global_form_id);
        return false;
    }

    auto* bytes = reinterpret_cast<std::uint8_t*>(form);
    bool ok = false;
    __try {
        const std::uint32_t flags = *reinterpret_cast<const std::uint32_t*>(
            bytes + offsets::FLAGS_OFF);
        if (flags & offsets::TESGLOBAL_FLAG_CONST) {
            FW_WRN("engine: apply_global_var refusing const global 0x%X",
                   global_form_id);
            return false;
        }
        *reinterpret_cast<float*>(bytes + offsets::TESGLOBAL_VALUE_OFF) = value;
        ok = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("engine: SEH in apply_global_var(0x%X, %g)",
               global_form_id, value);
        ok = false;
    }
    if (ok) {
        FW_LOG("engine: apply_global_var 0x%X = %g", global_form_id, value);
    }
    return ok;
}

void* resolve_inventory_entry_form(void* entry_ptr) {
    if (!entry_ptr) return nullptr;
    if (!g_ready.load(std::memory_order_acquire)) return nullptr;
    if (!g_inv_entry_to_form || !g_form_cache_slot) {
        FW_WRN("engine: resolve_inventory_entry_form: resolver not ready");
        return nullptr;
    }
    void* result = nullptr;
    __try {
        void* form_cache = *g_form_cache_slot;
        if (!form_cache) {
            FW_DBG("engine: resolve_inventory_entry_form: form_cache global is null "
                   "(engine not fully initialized?)");
            return nullptr;
        }
        result = g_inv_entry_to_form(form_cache, entry_ptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("engine: SEH in resolve_inventory_entry_form(%p)", entry_ptr);
        result = nullptr;
    }
    return result;
}

void* resolve_refhandle(void* handle_ptr) {
    if (!handle_ptr) return nullptr;
    if (!g_ready.load(std::memory_order_acquire) || !g_refhandle_resolve) {
        FW_WRN("engine: resolve_refhandle: resolver not ready");
        return nullptr;
    }
    void* result = nullptr;
    __try {
        // sub_14021E230(out, handle_ptr) writes the resolved REFR* into *out
        // (or leaves it null if the handle is stale).
        g_refhandle_resolve(&result, handle_ptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("engine: SEH in resolve_refhandle(%p)", handle_ptr);
        result = nullptr;
    }
    return result;
}

bool apply_container_op_to_engine(
    std::uint32_t kind,
    std::uint32_t container_form_id,
    std::uint32_t expected_base_id,
    std::uint32_t expected_cell_id,
    std::uint32_t item_base_id,
    std::int32_t  count)
{
    // Sanity + readiness.
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (container_form_id == 0 || item_base_id == 0 || count <= 0) {
        FW_DBG("engine: apply_container_op: early-out zero fields "
               "(cfid=0x%X iid=0x%X cnt=%d)",
               container_form_id, item_base_id, count);
        return false;
    }
    if (!g_engine_add_item || !g_engine_remove_item) {
        FW_WRN("engine: apply_container_op: add/remove fn pointers not resolved");
        return false;
    }

    // Resolve the REFR for the container on OUR side.
    void* container_ref = lookup_by_form_id(container_form_id);
    if (!container_ref) {
        // Container not loaded in our engine (cell not streamed in, different
        // save state, etc.). Not a bug — just a no-op apply.
        FW_DBG("engine: apply_container_op: container form 0x%X not found locally",
               container_form_id);
        return false;
    }

    // Identity check — refuse if (base, cell) don't match what the sender saw.
    // Guards against plugin-order drift and the 0xFF______ aliasing bug.
    const auto id = read_ref_identity(container_ref);
    const bool base_mismatch =
        (expected_base_id != 0) && (id.base_id != expected_base_id);
    const bool cell_mismatch =
        (expected_cell_id != 0) && (id.cell_id != expected_cell_id);
    if (base_mismatch || cell_mismatch) {
        FW_WRN("engine: apply_container_op: identity mismatch cfid=0x%X "
               "got=(base=0x%X cell=0x%X) expected=(base=0x%X cell=0x%X)",
               container_form_id,
               id.base_id, id.cell_id,
               expected_base_id, expected_cell_id);
        return false;
    }

    // Resolve the item form (TESForm*). The engine's AddItem/RemoveItem
    // accept a TESForm* and internally call GetAsBoundObject (vtable[51])
    // to reach the actual TESBoundObject* for items like MISC/WEAP/ARMO.
    // So passing the bare TESForm* is sufficient.
    void* item_form = lookup_by_form_id(item_base_id);
    if (!item_form) {
        FW_WRN("engine: apply_container_op: item form 0x%X not found",
               item_base_id);
        return false;
    }

    // B1.j.1: make sure the container's runtime inventory list is
    // materialized BEFORE we add/remove. The engine's AddItem lazily
    // materializes, so an Add would work either way — but a RemoveItem
    // on a never-touched container with a null REFR+0xF8 might no-op
    // or crash. Best to materialize first.
    (void)force_materialize_inventory(container_ref);

    const char* op_tag = "?";
    bool ok = false;
    __try {
        if (kind == 2 /* PUT */) {
            op_tag = "PUT";
            g_engine_add_item(
                container_ref,
                item_form,
                static_cast<std::uint32_t>(count),
                /*flag=*/0,
                /*vm_id=*/0,
                /*vm_state=*/nullptr);
            ok = true;
        } else if (kind == 1 /* TAKE */) {
            op_tag = "TAKE";
            g_engine_remove_item(
                container_ref,
                item_form,
                static_cast<std::uint32_t>(count),
                /*flag=*/0,
                /*dest_actor_refr=*/nullptr,  // nullptr = drop on ground
                                               // (nobody ever sees it — receiver's
                                               //  local world; peer A already took
                                               //  it on their side)
                /*flag2=*/0,
                /*vm_id=*/0,
                /*vm_state=*/nullptr);
            ok = true;
        } else {
            FW_WRN("engine: apply_container_op: unknown kind=%u", kind);
            return false;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("engine: SEH in apply_container_op_to_engine "
               "kind=%u cfid=0x%X iid=0x%X cnt=%d",
               kind, container_form_id, item_base_id, count);
        return false;
    }

    if (ok) {
        FW_LOG("engine: apply_container_op_to_engine %s cfid=0x%X "
               "(base=0x%X cell=0x%X) item=0x%X count=%d",
               op_tag, container_form_id,
               id.base_id, id.cell_id, item_base_id, count);
    }
    return ok;
}

bool force_materialize_inventory(void* container_ref) {
    if (!container_ref) return false;
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (!g_materialize_inv || !g_get_component) {
        FW_WRN("engine: force_materialize_inventory: resolvers not ready");
        return false;
    }

    bool already_materialized = false;
    void* list_after = nullptr;

    __try {
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(container_ref);

        // (1) Is the runtime list already populated?
        void* list_before = *reinterpret_cast<void* const*>(
            bytes + offsets::REFR_INV_LIST_OFF);
        if (list_before) {
            FW_DBG("engine: materialize skipped — list already present "
                   "ref=%p list=%p", container_ref, list_before);
            return true;
        }

        // (2) Get baseForm at REFR+0xE0. A null baseForm means the REFR
        //     is likely runtime-spawned without a template — nothing we
        //     can materialize from.
        void* base_form = *reinterpret_cast<void* const*>(
            bytes + offsets::BASE_FORM_OFF);
        if (!base_form) {
            FW_DBG("engine: materialize: no baseForm on ref=%p", container_ref);
            return false;
        }

        // (3) Is the baseForm a container? Ask for its CONT component.
        void* bgscont = g_get_component(base_form, offsets::TESFORM_SIG_CONT);
        if (!bgscont) {
            FW_DBG("engine: materialize: baseForm has no CONT component "
                   "(not a container) ref=%p base=%p", container_ref, base_form);
            return false;
        }

        // (4) Invoke the engine's own materializer. It allocates a
        //     0x80-byte BGSInventoryList, populates it from the CONT
        //     entries, and writes the ptr into REFR+0xF8.
        //     Return value is the post-init hook's output — we don't
        //     rely on it; we verify via memory read.
        (void)g_materialize_inv(container_ref, bgscont);

        list_after = *reinterpret_cast<void* const*>(
            bytes + offsets::REFR_INV_LIST_OFF);
        already_materialized = (list_after != nullptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("engine: SEH in force_materialize_inventory(%p)", container_ref);
        return false;
    }

    if (!already_materialized) {
        FW_WRN("engine: materialize returned but REFR+0xF8 still null "
               "ref=%p", container_ref);
        return false;
    }
    FW_LOG("engine: materialized runtime inventory list ref=%p list=%p",
           container_ref, list_after);
    return true;
}

std::size_t scan_container_inventory(
    void* container_ref,
    std::uint32_t* out_item_ids,
    std::int32_t*  out_counts,
    std::size_t    max_items)
{
    if (!container_ref || !out_item_ids || !out_counts || max_items == 0) return 0;
    if (!g_ready.load(std::memory_order_acquire) || !g_inv_item_count) return 0;

    // Cache fields outside __try so we don't create C++ objects inside it.
    std::size_t n = 0;
    const auto* cref = reinterpret_cast<const std::uint8_t*>(container_ref);

    __try {
        // REFR + 0xF8 → BGSInventoryList*. Null = never materialized (fresh
        // cell, pristine static loot table — we skip the seed, server will
        // trust client on first TAKE as in B0).
        void* list = *reinterpret_cast<void* const*>(cref + offsets::REFR_INV_LIST_OFF);
        if (!list) return 0;

        const auto* lbase = reinterpret_cast<const std::uint8_t*>(list);
        void* entries_start = *reinterpret_cast<void* const*>(
            lbase + offsets::INVLIST_ENTRIES_OFF);
        const std::uint32_t entry_count = *reinterpret_cast<const std::uint32_t*>(
            lbase + offsets::INVLIST_COUNT_OFF);

        if (!entries_start || entry_count == 0) return 0;

        auto* entry = reinterpret_cast<std::uint8_t*>(entries_start);
        std::uint32_t skipped_null_obj  = 0;
        std::uint32_t skipped_null_form = 0;
        std::uint32_t skipped_zero_cnt  = 0;
        for (std::uint32_t i = 0; i < entry_count && n < max_items; ++i,
             entry += offsets::INVENTORY_ITEM_STRIDE)
        {
            // entry + 0x00 → TESBoundObject* (item template)
            void* obj = *reinterpret_cast<void* const*>(
                entry + offsets::INVENTORY_ITEM_OBJ_OFF);
            if (!obj) { ++skipped_null_obj; continue; }

            // NOTE: previous revision here filtered entries with
            // formType == 0x38 ("LVLI") — that was WRONG. Re-read of
            // sub_140507660 shows the game counts EVERY entry in the
            // runtime list (REFR+0xF8) regardless of formType; the
            // formType check only applies in the fallback branch where
            // the runtime list is null and we walk the baseForm CONT.
            // Dropping that filter here was the root cause of "scan
            // only saw 2/4 items → server state incomplete → subsequent
            // TAKEs REJ_INSUFFICIENT" observed 2026-04-20 live.
            const std::uint8_t ftype = *reinterpret_cast<const std::uint8_t*>(
                reinterpret_cast<const std::uint8_t*>(obj) + offsets::FORMTYPE_OFF);
            (void)ftype;  // kept for future diagnostic logging if needed

            const std::uint32_t item_id = *reinterpret_cast<const std::uint32_t*>(
                reinterpret_cast<const std::uint8_t*>(obj) + offsets::FORMID_OFF);
            if (item_id == 0) { ++skipped_null_form; continue; }

            // Engine accessor: returns int32 stack count for this entry.
            int cnt = 0;
            __try { cnt = g_inv_item_count(entry); }
            __except (EXCEPTION_EXECUTE_HANDLER) { cnt = 0; }
            if (cnt <= 0) { ++skipped_zero_cnt; continue; }

            out_item_ids[n] = item_id;
            out_counts[n]   = cnt;
            ++n;
        }

        // Summary log at DEBUG so we can spot future scan-miss bugs at a glance.
        // Mismatch between entry_count and (n + skipped_*) would indicate we're
        // iterating off a different count field than the engine uses.
        if (skipped_null_obj || skipped_null_form || skipped_zero_cnt) {
            FW_DBG("engine: scan_container_inventory ref=%p: entry_count=%u "
                   "produced=%zu skipped_null_obj=%u skipped_null_form=%u "
                   "skipped_zero_cnt=%u",
                   container_ref, entry_count, n,
                   skipped_null_obj, skipped_null_form, skipped_zero_cnt);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("engine: SEH in scan_container_inventory(%p)", container_ref);
        return 0;
    }

    return n;
}

// -----------------------------------------------------------------------
// B5 scene view-proj capture (hot path — one call per frame).
//
// Chain (resolved 2026-04-22):
//   imgbase + PLAYER_CAMERA_SINGLETON_RVA -> PlayerCamera*
//   PlayerCamera + PLAYER_CAMERA_STATES_OFF -> states[0] = FirstPersonState*
//   FirstPersonState + TES_STATE_NICAM_OFF (0x50) -> NiCamera*
//   NiCamera + NI_CAMERA_VIEWPROJ_OFF (288) -> float[16] 4x4 matrix
//
// MATRIX SEMANTICS (cracked 2026-04-22, math verified against live capture):
// The matrix stored here is a row-major world-to-clip VP with FULL XYZ
// pre-subtract of player foot position baked into its design. The game
// expects input vectors as `pos_rel = (world - player_foot_pos)` with
// the camera eye sitting at (0, 0, 120) in this chunk coordinate system
// (= EYE_HEIGHT above the foot). Live capture values confirm:
//   row1[3] = 252.16 ≈ f · EYE_HEIGHT = 2.093 · 120 = 251.16  (Y-flip)
//   row2[3] = -1  → near plane N = 1
//   row3    = (forward, 0)  → no world-origin translation in perspective row
//
// Therefore: we return player's FOOT position in `out_eye_world` (NOT
// foot + EYE_HEIGHT). The shader does `pos_rel = world - foot_pos`.
// Prior code added +120 to z, which broke the math — caused the body to
// clip off-screen because the second eye-height subtraction shifted
// depth inconsistently.
//
// Returns false on any null / SEH. All reads SEH-caged; never crashes.
// -----------------------------------------------------------------------
bool read_scene_view_proj(float out_view_proj[16], float out_eye_world[3]) {
    const auto module_base = reinterpret_cast<std::uintptr_t>(
        GetModuleHandleW(L"Fallout4.exe"));
    if (!module_base) return false;

    const auto pc_slot = reinterpret_cast<void* const*>(
        module_base + offsets::PLAYER_CAMERA_SINGLETON_RVA);

    void* pc = nullptr;
    __try { pc = *pc_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    if (!pc) return false;

    __try {
        const auto* pc_bytes = reinterpret_cast<const std::uint8_t*>(pc);
        // states[0] = FirstPersonState* (always populated once in-game)
        const auto state = *reinterpret_cast<void* const*>(
            pc_bytes + offsets::PLAYER_CAMERA_STATES_OFF);
        if (!state) return false;

        const auto* st_bytes = reinterpret_cast<const std::uint8_t*>(state);
        const auto nicam = *reinterpret_cast<void* const*>(
            st_bytes + offsets::TES_STATE_NICAM_OFF);
        if (!nicam) return false;

        // Sanity: first qword of nicam must be the NiCamera vtable.
        const auto nicam_vtbl = *reinterpret_cast<void* const*>(nicam);
        if (reinterpret_cast<std::uintptr_t>(nicam_vtbl) !=
            module_base + offsets::NI_CAMERA_VTABLE_RVA) {
            return false;
        }

        // Copy 64 bytes of cached matrix.
        const auto* mat_src = reinterpret_cast<const float*>(
            reinterpret_cast<const std::uint8_t*>(nicam) +
            offsets::NI_CAMERA_VIEWPROJ_OFF);
        std::memcpy(out_view_proj, mat_src, 64);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    // Chunk-subtraction origin = player FOOT position (NOT eye = foot+120).
    // The matrix already bakes EYE_HEIGHT=120 into its translation column;
    // adding 120 here would double-subtract and clip the body off-screen.
    // See the SEMANTICS block above for the math derivation.
    const auto pchar_slot = reinterpret_cast<void* const*>(
        module_base + offsets::PLAYER_SINGLETON_RVA);
    void* pchar = nullptr;
    __try { pchar = *pchar_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    if (!pchar) return false;

    __try {
        const auto* b = reinterpret_cast<const std::uint8_t*>(pchar);
        out_eye_world[0] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 0);
        out_eye_world[1] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 4);
        out_eye_world[2] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 8);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    return true;
}

// -----------------------------------------------------------------------
// β.6 shake fix — read live render-frame eye (bob-aware).
//
// The attempt to read NiCamera::world.translate (+0xA0) FAILED: that
// field holds only the LOCAL eye offset (0, 0, 120) relative to the
// camera's parent, because PlayerCamera doesn't drive NiCamera through
// UpdateWorldData. Instead, PlayerCamera caches the current-frame world
// eye position at its OWN +0x188 (see offsets.h for proof).
//
// We keep the old signature `read_camera_world_transform(eye, basis)`
// for ABI continuity, but basis is no longer populated (caller ignored
// it anyway). If future work needs camera orientation, read it from the
// captured `worldToCam` matrix or from PC's own rotation quaternion.
// -----------------------------------------------------------------------
bool read_camera_world_transform(float out_eye_world[3],
                                  float out_basis_rows[9]) {
    if (out_basis_rows) {
        // Basis is not set by this function anymore — identity fallback
        // to avoid undefined reads in the caller.
        for (int i = 0; i < 9; ++i) out_basis_rows[i] = 0.0f;
        out_basis_rows[0] = 1.0f;  // row0.x
        out_basis_rows[4] = 1.0f;  // row1.y
        out_basis_rows[8] = 1.0f;  // row2.z
    }

    const auto module_base = reinterpret_cast<std::uintptr_t>(
        GetModuleHandleW(L"Fallout4.exe"));
    if (!module_base) return false;

    const auto pc_slot = reinterpret_cast<void* const*>(
        module_base + offsets::PLAYER_CAMERA_SINGLETON_RVA);

    void* pc = nullptr;
    __try { pc = *pc_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    if (!pc) return false;

    __try {
        const auto* pc_bytes = reinterpret_cast<const std::uint8_t*>(pc);

        // Validate the buffered-pos flag at +0x1A7. If 0, the value at
        // +0x188 hasn't been populated yet (e.g., first frames or
        // state transition) — treat as failure so caller can fall back.
        const auto valid = *reinterpret_cast<const std::uint8_t*>(
            pc_bytes + offsets::PLAYER_CAMERA_BUF_VAL_OFF);
        if (valid == 0) return false;

        const auto* eye_ptr = reinterpret_cast<const float*>(
            pc_bytes + offsets::PLAYER_CAMERA_BUF_POS_OFF);
        out_eye_world[0] = eye_ptr[0];
        out_eye_world[1] = eye_ptr[1];
        out_eye_world[2] = eye_ptr[2];
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    return true;
}

// -----------------------------------------------------------------------
// β.6b v5 — read live NiFrustum near/far from PlayerCamera's NiCamera.
// Layout per CommonLibF4: NiFrustum at NiCamera+0x160, fields are
// {left, right, top, bottom, near, far, ortho} — near @ +0x10, far @
// +0x14 into the frustum. Values are the current-frame scene camera's
// clip planes used to build VP.
// -----------------------------------------------------------------------
bool read_camera_frustum_near_far(float& out_near, float& out_far) {
    const auto module_base = reinterpret_cast<std::uintptr_t>(
        GetModuleHandleW(L"Fallout4.exe"));
    if (!module_base) return false;

    const auto pc_slot = reinterpret_cast<void* const*>(
        module_base + offsets::PLAYER_CAMERA_SINGLETON_RVA);
    void* pc = nullptr;
    __try { pc = *pc_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    if (!pc) return false;

    __try {
        const auto* pc_bytes = reinterpret_cast<const std::uint8_t*>(pc);
        const auto state = *reinterpret_cast<void* const*>(
            pc_bytes + offsets::PLAYER_CAMERA_STATES_OFF);
        if (!state) return false;

        const auto* st_bytes = reinterpret_cast<const std::uint8_t*>(state);
        const auto nicam = *reinterpret_cast<void* const*>(
            st_bytes + offsets::TES_STATE_NICAM_OFF);
        if (!nicam) return false;

        const auto nicam_vtbl = *reinterpret_cast<void* const*>(nicam);
        if (reinterpret_cast<std::uintptr_t>(nicam_vtbl) !=
            module_base + offsets::NI_CAMERA_VTABLE_RVA) {
            return false;
        }

        const auto* ni_bytes = reinterpret_cast<const std::uint8_t*>(nicam);
        const auto* frustum_base = ni_bytes + offsets::NI_CAMERA_FRUSTUM_OFF;
        out_near = *reinterpret_cast<const float*>(
            frustum_base + offsets::NI_FRUSTUM_NEAR_OFF);
        out_far = *reinterpret_cast<const float*>(
            frustum_base + offsets::NI_FRUSTUM_FAR_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    // Sanity: plausible values?
    if (out_near <= 0.0f || out_near > 1000.0f) return false;
    if (out_far  <= out_near || out_far > 1e10f) return false;
    return true;
}

// -----------------------------------------------------------------------
// β.6 shake fix v2 — extract forward direction from worldToCam row 3.
//
// In row-major VP matrix, row 3 is the perspective-divide row, which
// encodes the camera-forward unit vector (fx, fy, fz, 0). Reading this
// gives the game's actual frame-perfect camera orientation (smoothed,
// interpolated by the engine) — matches what the scene was rendered
// with, no angular jitter vs. actor rot[] raw input.
// -----------------------------------------------------------------------
bool read_camera_forward(float out_fwd[3]) {
    const auto module_base = reinterpret_cast<std::uintptr_t>(
        GetModuleHandleW(L"Fallout4.exe"));
    if (!module_base) return false;

    const auto pc_slot = reinterpret_cast<void* const*>(
        module_base + offsets::PLAYER_CAMERA_SINGLETON_RVA);
    void* pc = nullptr;
    __try { pc = *pc_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    if (!pc) return false;

    __try {
        const auto* pc_bytes = reinterpret_cast<const std::uint8_t*>(pc);
        const auto state = *reinterpret_cast<void* const*>(
            pc_bytes + offsets::PLAYER_CAMERA_STATES_OFF);
        if (!state) return false;

        const auto* st_bytes = reinterpret_cast<const std::uint8_t*>(state);
        const auto nicam = *reinterpret_cast<void* const*>(
            st_bytes + offsets::TES_STATE_NICAM_OFF);
        if (!nicam) return false;

        // Validate NiCamera vtable.
        const auto nicam_vtbl = *reinterpret_cast<void* const*>(nicam);
        if (reinterpret_cast<std::uintptr_t>(nicam_vtbl) !=
            module_base + offsets::NI_CAMERA_VTABLE_RVA) {
            return false;
        }

        // Row 3 of row-major 4x4 = mem[12..15].
        const auto* m = reinterpret_cast<const float*>(
            reinterpret_cast<const std::uint8_t*>(nicam) +
            offsets::NI_CAMERA_VIEWPROJ_OFF);
        const float fx = m[12];
        const float fy = m[13];
        const float fz = m[14];

        // Sanity: forward should be ~unit length.
        const float mag2 = fx*fx + fy*fy + fz*fz;
        if (mag2 < 0.9f || mag2 > 1.1f) {
            // Matrix is in a weird state (shadow/UI/post-process pass,
            // or mid-write). Fall back.
            return false;
        }

        const float inv_mag = 1.0f / std::sqrt(mag2);
        out_fwd[0] = fx * inv_mag;
        out_fwd[1] = fy * inv_mag;
        out_fwd[2] = fz * inv_mag;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    return true;
}

// -----------------------------------------------------------------------
// β.6 camera-eye probe — dump candidate offsets for frame-perfect eye.
//
// RE leads (2026-04-22 from CommonLibF4 + SSE cross-ref):
//   PlayerCamera+0x188 : bufferedCameraPos (NiPoint3)
//   PlayerCamera+0x1A7 : cameraPosBuffered (bool flag)
//   FirstPersonState+0x30 : lastPosition     (SSE analog)
//   FirstPersonState+0x3C : lastFrameSpringVelocity (SSE analog)
//   FirstPersonState+0x48 : dampeningOffset  (SSE analog, bob delta)
//   FirstPersonState+0x54 : ??? next NiPoint3 slot
//
// We also log actor foot pos for reference — whatever tracks it with a
// +120-ish z offset + oscillates during walking is the bob-aware eye.
// -----------------------------------------------------------------------
void probe_camera_eye_fields() {
    if (!g_ready.load(std::memory_order_acquire)) return;

    const auto module_base = reinterpret_cast<std::uintptr_t>(
        GetModuleHandleW(L"Fallout4.exe"));
    if (!module_base) return;

    // Player actor foot pos (ground truth).
    const auto pchar_slot = reinterpret_cast<void* const*>(
        module_base + offsets::PLAYER_SINGLETON_RVA);
    void* pchar = nullptr;
    __try { pchar = *pchar_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    if (!pchar) return;

    float foot[3]{};
    __try {
        const auto* b = reinterpret_cast<const std::uint8_t*>(pchar);
        foot[0] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 0);
        foot[1] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 4);
        foot[2] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 8);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return; }

    const auto pc_slot = reinterpret_cast<void* const*>(
        module_base + offsets::PLAYER_CAMERA_SINGLETON_RVA);
    void* pc = nullptr;
    __try { pc = *pc_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    if (!pc) return;

    __try {
        const auto* pc_bytes = reinterpret_cast<const std::uint8_t*>(pc);

        // PlayerCamera+0x188 = bufferedCameraPos
        const float* pc188 = reinterpret_cast<const float*>(pc_bytes + 0x188);
        const std::uint8_t* pc1a7 = pc_bytes + 0x1A7;
        FW_LOG("[eyeprobe] foot=(%.1f, %.1f, %.1f)  "
               "PC+0x188 bufferedCameraPos=(%.1f, %.1f, %.1f) "
               "PC+0x1A7 flag=%u",
               foot[0], foot[1], foot[2],
               pc188[0], pc188[1], pc188[2],
               *pc1a7);

        // states[0] = FirstPersonState
        const auto state = *reinterpret_cast<void* const*>(
            pc_bytes + offsets::PLAYER_CAMERA_STATES_OFF);
        if (!state) return;
        const auto* fs = reinterpret_cast<const std::uint8_t*>(state);

        // Scan FirstPersonState+0x28..0x90 as NiPoint3 (every 4 bytes,
        // look for 3-float clusters that have player-pos-scale values).
        FW_LOG("[eyeprobe] FirstPersonState candidate eye fields:");
        for (std::size_t off = 0x28; off <= 0x80; off += 4) {
            const float* f = reinterpret_cast<const float*>(fs + off);
            // Heuristic filter: only print if first float is in player
            // coord range (|f[0]| > 100) — otherwise it's noise.
            if (std::fabs(f[0]) > 100.0f && std::fabs(f[0]) < 1e6f) {
                FW_LOG("[eyeprobe]   FS+0x%02zX = (%10.1f, %10.1f, %10.1f)",
                       off, f[0], f[1], f[2]);
            }
        }

        // Specifically dump the "known SSE" offsets unconditionally.
        const float* fs30 = reinterpret_cast<const float*>(fs + 0x30);
        const float* fs3c = reinterpret_cast<const float*>(fs + 0x3C);
        const float* fs48 = reinterpret_cast<const float*>(fs + 0x48);
        const float* fs54 = reinterpret_cast<const float*>(fs + 0x54);
        FW_LOG("[eyeprobe]   FS+0x30 (sse=lastPosition)      = (%.1f, %.1f, %.1f)",
               fs30[0], fs30[1], fs30[2]);
        FW_LOG("[eyeprobe]   FS+0x3C (sse=lastSpringVelocity)= (%.1f, %.1f, %.1f)",
               fs3c[0], fs3c[1], fs3c[2]);
        FW_LOG("[eyeprobe]   FS+0x48 (sse=dampeningOffset)   = (%.1f, %.1f, %.1f)",
               fs48[0], fs48[1], fs48[2]);
        FW_LOG("[eyeprobe]   FS+0x54 (next NiPoint3 slot)    = (%.1f, %.1f, %.1f)",
               fs54[0], fs54[1], fs54[2]);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[eyeprobe] SEH during probe");
    }
}

// -----------------------------------------------------------------------
// B5 diagnostic — PlayerCamera layout probe.
//
// We scan the singleton's first 0x200 bytes looking for qwords that
// dereference to the known NiCamera vtable VA. Each match is logged;
// stable matches across frames identify the "OFF_NICAM" we need to
// navigate PlayerCamera → NiCamera at runtime. One-shot.
// -----------------------------------------------------------------------
static std::atomic<bool> g_camera_probe_done{false};

// Parallel probe: scan MainCullingCamera (the scene-render culling
// camera) for an internal NiCamera*. MCC is a BSTSingletonSDM with
// its instance at a fixed RVA (not derived from PlayerCamera). Hits
// give us a second candidate for the "real" scene VP matrix.
void probe_main_culling_camera_once() {
    static std::atomic<bool> done{false};
    if (done.load(std::memory_order_acquire)) return;
    if (!g_ready.load(std::memory_order_acquire)) return;

    const auto module_base = reinterpret_cast<std::uintptr_t>(
        GetModuleHandleW(L"Fallout4.exe"));
    if (!module_base) return;

    const auto ni_vtbl = module_base + offsets::NI_CAMERA_VTABLE_RVA;
    const auto mcc_vtbl = module_base + offsets::MAIN_CULLING_CAMERA_VTABLE_RVA;

    // Try both accessors: direct (instance at fixed RVA) and via ptr slot.
    const auto direct_instance = reinterpret_cast<const std::uint8_t*>(
        module_base + offsets::MAIN_CULLING_CAMERA_INSTANCE_RVA);
    void* via_slot = nullptr;
    __try {
        via_slot = *reinterpret_cast<void* const*>(
            module_base + offsets::MAIN_CULLING_CAMERA_PTR_SLOT_RVA);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    FW_LOG("[mccprobe] direct_instance=%p via_slot=%p  (should be same)",
           static_cast<const void*>(direct_instance),
           via_slot);

    // Use the via_slot if non-null else fall back to direct.
    const auto* mcc = via_slot
        ? reinterpret_cast<const std::uint8_t*>(via_slot)
        : direct_instance;

    // Verify vtable matches MainCullingCamera.
    __try {
        const auto vt = *reinterpret_cast<void* const*>(mcc);
        const auto vt_va = reinterpret_cast<std::uintptr_t>(vt);
        FW_LOG("[mccprobe] MCC[0] = vtable 0x%llX (expected MCC 0x%llX, "
               "match=%d)",
               static_cast<unsigned long long>(vt_va),
               static_cast<unsigned long long>(mcc_vtbl),
               vt_va == mcc_vtbl ? 1 : 0);
        if (vt_va != mcc_vtbl) {
            FW_WRN("[mccprobe] MCC vtable mismatch — instance not initialized yet?");
            return;  // retry next frame
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[mccprobe] SEH reading MCC vtable");
        return;
    }

    // MCC IS-A NiCamera (extends it), so its own vtable != NiCamera vtable.
    // The NiCamera-inherited fields live at SAME offsets within MCC as in
    // NiCamera. So the cached matrix at NiCamera+288 lives at MCC+288.
    (void)ni_vtbl;

    // Dump the 4x4 matrix at MCC+288 directly.
    __try {
        const float* m = reinterpret_cast<const float*>(
            mcc + offsets::NI_CAMERA_VIEWPROJ_OFF);
        FW_LOG("[mccprobe] MCC+288 matrix (inherited NiCamera viewproj):");
        FW_LOG("[mccprobe]   row0=[%8.3f %8.3f %8.3f %12.2f]",
               m[0], m[1], m[2], m[3]);
        FW_LOG("[mccprobe]   row1=[%8.3f %8.3f %8.3f %12.2f]",
               m[4], m[5], m[6], m[7]);
        FW_LOG("[mccprobe]   row2=[%8.3f %8.3f %8.3f %12.2f]",
               m[8], m[9], m[10], m[11]);
        FW_LOG("[mccprobe]   row3=[%8.3f %8.3f %8.3f %12.2f]",
               m[12], m[13], m[14], m[15]);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[mccprobe] SEH reading MCC+288");
        return;
    }

    // Also dump a few other interesting offsets for MCC layout (the
    // cached world transform, eye position, frustum params).
    __try {
        const float* f160 = reinterpret_cast<const float*>(mcc + 160);
        FW_LOG("[mccprobe]   MCC+160 [%8.3f %8.3f %8.3f]",
               f160[0], f160[1], f160[2]);
        const float* f352 = reinterpret_cast<const float*>(mcc + 352);
        FW_LOG("[mccprobe]   MCC+352 (frustum L/R/T/B N/F) "
               "[%8.3f %8.3f %8.3f %8.3f %8.3f %8.3f]",
               f352[0], f352[1], f352[2], f352[3], f352[4], f352[5]);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    FW_LOG("[mccprobe] MCC probe complete — matrix dumped.");
    done.store(true, std::memory_order_release);
}

void probe_camera_layout_once() {
    if (g_camera_probe_done.load(std::memory_order_acquire)) return;
    if (!g_ready.load(std::memory_order_acquire)) return;

    const auto module_base = reinterpret_cast<std::uintptr_t>(
        GetModuleHandleW(L"Fallout4.exe"));
    if (!module_base) return;

    const auto pc_slot = reinterpret_cast<void* const*>(
        module_base + offsets::PLAYER_CAMERA_SINGLETON_RVA);
    const auto ni_camera_vtable_va =
        module_base + offsets::NI_CAMERA_VTABLE_RVA;

    void* pc = nullptr;
    __try { pc = *pc_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_DBG("[camprobe] SEH reading PlayerCamera singleton (not ready)");
        return;
    }
    if (!pc) {
        FW_DBG("[camprobe] PlayerCamera singleton null (not ready)");
        return;
    }

    FW_LOG("[camprobe] scanning PlayerCamera=%p for NiCamera vtable=0x%llX",
           pc, static_cast<unsigned long long>(ni_camera_vtable_va));

    const auto* bytes = reinterpret_cast<const std::uint8_t*>(pc);
    int matches = 0;

    // Scan PlayerCamera[0..0x1B0] as qwords. For each non-null pointer,
    // deref and check if the first qword at that target equals the
    // NiCamera vtable VA.
    __try {
        for (std::size_t off = 0; off < 0x1C0; off += 8) {
            const auto candidate = *reinterpret_cast<void* const*>(bytes + off);
            if (!candidate) continue;

            // Heuristic: pointer must be within a sensible process
            // address range (x64 user-space, above 0x10000).
            const auto cva = reinterpret_cast<std::uintptr_t>(candidate);
            if (cva < 0x10000ull || cva > 0x7FFFFFFFFFFFull) continue;

            void* first_qword = nullptr;
            __try {
                first_qword = *reinterpret_cast<void* const*>(candidate);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
            const auto fva = reinterpret_cast<std::uintptr_t>(first_qword);

            // Exact NiCamera vtable match.
            if (fva == ni_camera_vtable_va) {
                FW_LOG("[camprobe] PlayerCamera+0x%zX -> NiCamera* %p "
                       "(vtable match)", off, candidate);
                ++matches;
                continue;
            }

            // Secondary: pointer-to-pointer (smart-ptr wrapper) —
            // deref twice.
            if (fva > 0x10000ull && fva < 0x7FFFFFFFFFFFull) {
                void* second_qword = nullptr;
                __try {
                    second_qword = *reinterpret_cast<void* const*>(first_qword);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    continue;
                }
                const auto sva = reinterpret_cast<std::uintptr_t>(second_qword);
                if (sva == ni_camera_vtable_va) {
                    FW_LOG("[camprobe] PlayerCamera+0x%zX -> smart_ptr -> "
                           "NiCamera* %p (indirect vtable match)",
                           off, first_qword);
                    ++matches;
                }
            }
        }

        // Also scan each slot of the states array (+0xE0..+0x158) — each
        // is a TESCameraState*. For the ACTIVE state, look INSIDE it for
        // a NiCamera pointer.
        const auto active_idx = *reinterpret_cast<const std::int32_t*>(
            bytes + offsets::PLAYER_CAMERA_ACTIVE_OFF);
        FW_LOG("[camprobe] active_state_idx = %d (raw dword @ +0x1A0)",
               active_idx);

        // Dump likely "current state pointer" caches at +0x170 and +0x178.
        const auto ptr_170 = *reinterpret_cast<void* const*>(bytes + 0x170);
        const auto ptr_178 = *reinterpret_cast<void* const*>(bytes + 0x178);
        FW_LOG("[camprobe] cached-state candidates: "
               "PlayerCamera+0x170 = %p,  +0x178 = %p",
               ptr_170, ptr_178);

        for (int i = 0; i < 16; ++i) {
            const std::size_t slot_off = offsets::PLAYER_CAMERA_STATES_OFF + i * 8;
            if (slot_off >= 0x1C0) break;
            const auto state_ptr = *reinterpret_cast<void* const*>(
                bytes + slot_off);
            if (!state_ptr) continue;

            const auto sva = reinterpret_cast<std::uintptr_t>(state_ptr);
            if (sva < 0x10000ull || sva > 0x7FFFFFFFFFFFull) continue;

            // State object's first qword is its vtable.
            void* state_vt = nullptr;
            __try {
                state_vt = *reinterpret_cast<void* const*>(state_ptr);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
            const auto svt = reinterpret_cast<std::uintptr_t>(state_vt);
            const auto state_vt_rva = (svt > module_base) ? (svt - module_base) : 0;
            FW_LOG("[camprobe]   state[%d] @ +0x%zX = %p  vtable=0x%llX (RVA 0x%llX)",
                   i, slot_off, state_ptr,
                   static_cast<unsigned long long>(svt),
                   static_cast<unsigned long long>(state_vt_rva));

            // Scan first 0x100 bytes of the state object for NiCamera ptr.
            const auto* sbytes = reinterpret_cast<const std::uint8_t*>(state_ptr);
            for (std::size_t soff = 0; soff < 0x120; soff += 8) {
                void* cand = nullptr;
                __try {
                    cand = *reinterpret_cast<void* const*>(sbytes + soff);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    continue;
                }
                const auto cva = reinterpret_cast<std::uintptr_t>(cand);
                if (cva < 0x10000ull || cva > 0x7FFFFFFFFFFFull) continue;

                void* fq = nullptr;
                __try { fq = *reinterpret_cast<void* const*>(cand); }
                __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
                const auto fva = reinterpret_cast<std::uintptr_t>(fq);
                if (fva == ni_camera_vtable_va) {
                    FW_LOG("[camprobe]     state[%d]+0x%zX -> NiCamera* %p "
                           "(\u2705 vtable match)",
                           i, soff, cand);
                    ++matches;

                    // Bonus: dump the 4x4 float matrix at NiCamera+288
                    // (from IDA clone method — candidate view-proj).
                    const auto* ncam_bytes = reinterpret_cast<const std::uint8_t*>(cand);
                    __try {
                        const float* m = reinterpret_cast<const float*>(
                            ncam_bytes + offsets::NI_CAMERA_VIEWPROJ_OFF);
                        FW_LOG("[camprobe]       NiCamera+288 matrix 4x4:");
                        FW_LOG("[camprobe]         row0=[%10.3f %10.3f %10.3f %10.3f]",
                               m[0],  m[1],  m[2],  m[3]);
                        FW_LOG("[camprobe]         row1=[%10.3f %10.3f %10.3f %10.3f]",
                               m[4],  m[5],  m[6],  m[7]);
                        FW_LOG("[camprobe]         row2=[%10.3f %10.3f %10.3f %10.3f]",
                               m[8],  m[9],  m[10], m[11]);
                        FW_LOG("[camprobe]         row3=[%10.3f %10.3f %10.3f %10.3f]",
                               m[12], m[13], m[14], m[15]);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        FW_WRN("[camprobe]       SEH reading NiCamera+288 matrix");
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[camprobe] SEH during scan");
        return;
    }

    FW_LOG("[camprobe] scan complete: %d NiCamera pointer matches found", matches);
    if (matches > 0) {
        g_camera_probe_done.store(true, std::memory_order_release);
    }
    // Else: keep retrying next frame until PlayerCamera is populated.
}

// -----------------------------------------------------------------------
// Z.2 (Path B) — spawn a ghost Actor via PlaceAtMe native.
//
// MUST be called from the main (WndProc) thread. See
// re/placeatme_calling_convention.txt for the full signature decode.
// -----------------------------------------------------------------------
void* spawn_ghost_actor(std::uint32_t template_form_id) {
    if (!g_ready.load(std::memory_order_acquire)) {
        FW_ERR("[ghost] spawn: engine not ready");
        return nullptr;
    }
    if (!g_place_at_me || !g_lookup || !g_player_singleton_slot) {
        FW_ERR("[ghost] spawn: resolvers null "
               "(place=%p lookup=%p player_slot=%p)",
               g_place_at_me, g_lookup, g_player_singleton_slot);
        return nullptr;
    }

    // Resolve template form (e.g., LCharWorkshopNPC settler).
    void* template_form = nullptr;
    __try { template_form = g_lookup(template_form_id); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[ghost] spawn: SEH in lookup(0x%X)", template_form_id);
        return nullptr;
    }
    if (!template_form) {
        FW_ERR("[ghost] spawn: lookup(0x%X) returned null — "
               "ESM not loaded? worldspace unavailable?", template_form_id);
        return nullptr;
    }

    // Resolve player REFR (the "at me" anchor). Read-then-use to avoid
    // holding a stale pointer across re-load.
    void* player = nullptr;
    __try { player = *g_player_singleton_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[ghost] spawn: SEH reading player singleton");
        return nullptr;
    }
    if (!player) {
        FW_ERR("[ghost] spawn: player singleton null — not in game yet?");
        return nullptr;
    }

    // Form pair { VMHandle=null, TESForm*=template }. Decomp shows PlaceAtMe
    // reads *a3 first (handle path); NULL handle → falls back to a3[1]
    // direct TESForm*, which is what we want.
    void* form_pair[2] = { nullptr, template_form };

    void* actor = nullptr;
    __try {
        actor = g_place_at_me(
            /* vm         = */ nullptr,
            /* stack_id   = */ 0,
            /* form_pair  = */ form_pair,
            /* anchor     = */ player,
            /* count      = */ 1,
            /* persistent = */ 0);  // 0 = temp ref, skip MarkPersistent
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[ghost] spawn: SEH in PlaceAtMe(template=0x%X)",
               template_form_id);
        return nullptr;
    }

    if (!actor) {
        FW_ERR("[ghost] spawn: PlaceAtMe returned null (template=0x%X)",
               template_form_id);
        return nullptr;
    }

    // OR in the TEMPORARY flag so this ref doesn't persist in the save.
    // PlaceAtMe hardcodes NEW_REFR_DATA.flags = 0x1000000 only; we patch
    // the resulting REFR's flags field post-return.
    auto* actor_bytes = reinterpret_cast<std::uint8_t*>(actor);
    __try {
        auto* flags_ptr = reinterpret_cast<std::uint32_t*>(
            actor_bytes + offsets::FLAGS_OFF);
        *flags_ptr |= offsets::REFR_FLAG_TEMPORARY;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[ghost] spawn: SEH patching TEMPORARY flag on actor=%p",
               actor);
        // Non-fatal — worst case is save bloat, we still got an actor.
    }

    // Read back the resulting form_id for logging.
    std::uint32_t actor_form_id = 0;
    __try {
        actor_form_id = *reinterpret_cast<const std::uint32_t*>(
            actor_bytes + offsets::FORMID_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    FW_LOG("[ghost] spawn OK: template=0x%X \u2192 actor=%p form_id=0x%X "
           "(TEMPORARY patched)",
           template_form_id, actor, actor_form_id);
    return actor;
}

} // namespace fw::engine
