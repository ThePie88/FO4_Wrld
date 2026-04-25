#include "ref_identity.h"

#include <windows.h>
#include <cstdint>

#include "offsets.h"

namespace fw {

namespace {

// SEH-safe field read. Returns `fallback` if the memory at `addr` is not
// accessible. Much cheaper than VirtualQuery + manual probe — we just catch
// the AV if it happens. Hot path uses this dozens of times; a try/except
// at each call is still sub-microsecond.
template <typename T>
T safe_read(const void* addr, T fallback) noexcept {
    if (!addr) return fallback;
    __try {
        return *reinterpret_cast<const T*>(addr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return fallback;
    }
}

} // namespace

RefIdentity read_ref_identity(void* ref) noexcept {
    RefIdentity id{};
    if (!ref) return id;

    const auto* base = reinterpret_cast<const std::uint8_t*>(ref);

    // 1. REFR's own formID (TESForm.formID at +0x14).
    id.form_id = safe_read<std::uint32_t>(base + offsets::FORMID_OFF, 0u);

    // 2. baseForm.formID — deref pointer at +0xE0 then read +0x14.
    void* base_form = safe_read<void*>(base + offsets::BASE_FORM_OFF, nullptr);
    if (base_form) {
        id.base_id = safe_read<std::uint32_t>(
            reinterpret_cast<const std::uint8_t*>(base_form) + offsets::FORMID_OFF, 0u);
    }

    // 3. parentCell.formID — deref pointer at +0xB8 then read +0x14.
    void* cell = safe_read<void*>(base + offsets::PARENT_CELL_OFF, nullptr);
    if (cell) {
        id.cell_id = safe_read<std::uint32_t>(
            reinterpret_cast<const std::uint8_t*>(cell) + offsets::FORMID_OFF, 0u);
    }

    return id;
}

bool is_player(void* ref) noexcept {
    if (!ref) return false;
    const auto* base = reinterpret_cast<const std::uint8_t*>(ref);
    return safe_read<std::uint32_t>(
        base + offsets::FORMID_OFF, 0u) == offsets::PLAYER_FORMID;
}

} // namespace fw
