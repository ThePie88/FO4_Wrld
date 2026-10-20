#include "instance_fp.h"

#include <cmath>
#include <cstring>

#include "../log.h"
#include "../net/protocol.h"
#include "inventory_capture.h"

namespace fw::persist::instance {

namespace {

struct Fnv {
    std::uint64_t h = 0xCBF29CE484222325ull;
    void bytes(const void* p, std::size_t n) noexcept {
        const auto* b = static_cast<const std::uint8_t*>(p);
        for (std::size_t i = 0; i < n; ++i) { h ^= b[i]; h *= 0x100000001B3ull; }
    }
    void u8(std::uint8_t v) noexcept { bytes(&v, 1); }
    void u16(std::uint16_t v) noexcept { bytes(&v, 2); }   // little-endian host
    void u32(std::uint32_t v) noexcept { bytes(&v, 4); }
    void i32(std::int32_t v) noexcept { bytes(&v, 4); }
};

// round(health * 1000), half away from zero, the f32 widened to double the
// way protocol.py does it (_health_q). Spelled out instead of std::lround so
// the two sides share the exact rule, not just the intent.
std::int32_t health_q(float health) noexcept {
    const double v = static_cast<double>(health) * 1000.0;
    const double a = std::fabs(v);
    const double fl = std::floor(a);
    long long q = static_cast<long long>(fl) + ((a - fl) >= 0.5 ? 1 : 0);
    if (v < 0) q = -q;
    return static_cast<std::int32_t>(q);
}

} // namespace

std::uint64_t fp_of(std::uint32_t base, const fw::net::InstanceDesc& d) noexcept {
    const bool has_oie    = (d.flags & fw::net::kInstanceFlagOie) != 0;
    const bool has_health = (d.flags & fw::net::kInstanceFlagHealth) != 0;
    if (!has_oie && !has_health) return fw::net::kFpPlain;
    Fnv f;
    f.u32(base);
    f.u8(has_oie ? 1 : 0);
    if (has_oie) {
        const std::uint8_t n = d.mod_n < fw::net::kInstanceMaxMods
                             ? d.mod_n : static_cast<std::uint8_t>(fw::net::kInstanceMaxMods);
        // Sorted by (form, attach, rank): the engine's order of the records is
        // not part of what the instance is. Insertion sort on a copy.
        fw::net::InstanceMod m[fw::net::kInstanceMaxMods];
        for (std::uint8_t i = 0; i < n; ++i) m[i] = d.mods[i];
        for (std::uint8_t i = 1; i < n; ++i) {
            const fw::net::InstanceMod key = m[i];
            int j = i;
            while (j > 0) {
                const fw::net::InstanceMod& p = m[j - 1];
                const bool after = p.form != key.form ? p.form > key.form
                                 : p.attach != key.attach ? p.attach > key.attach
                                 : p.rank > key.rank;
                if (!after) break;
                m[j] = m[j - 1];
                --j;
            }
            m[j] = key;
        }
        f.u16(d.tmpl);
        f.u8(n);
        for (std::uint8_t i = 0; i < n; ++i) { f.u32(m[i].form); f.u8(m[i].attach); f.u8(m[i].rank); }
    }
    f.u8(has_health ? 1 : 0);
    if (has_health) f.i32(health_q(d.health));
    std::uint64_t h = f.h;
    if (h == fw::net::kFpPlain || h == fw::net::kFpUnknown) h = 1;
    return h;
}

bool desc_of(const fw::persist::inventory::StackRecord& r, fw::net::InstanceDesc* out) noexcept {
    if (!out) return false;
    std::memset(out, 0, sizeof(*out));
    out->tmpl = 0xFFFF;
    out->health = -1.0f;
    // A node of a persisted type whose vtable did not match was not decoded:
    // it may be the OIE or the Health extra, so the instance is not known.
    if (r.unverified_types != 0) return false;
    if (r.oie_truncated || r.oie_count > fw::net::kInstanceMaxMods) return false;
    if (r.extra_mask & fw::persist::inventory::MASK_OIE) {
        out->flags |= fw::net::kInstanceFlagOie;
        out->tmpl = r.oie_template;
        out->mod_n = r.oie_count;
        for (std::uint8_t i = 0; i < r.oie_count; ++i) {
            out->mods[i].form   = r.oie[i].mod_form_id;
            out->mods[i].attach = r.oie[i].attach_index;
            out->mods[i].rank   = r.oie[i].rank;
        }
    }
    if (!std::isnan(r.health)) {
        out->flags |= fw::net::kInstanceFlagHealth;
        out->health = r.health;
    }
    return true;
}

std::uint64_t fp_of_record(const fw::persist::inventory::StackRecord& r,
                           fw::net::InstanceDesc* out) noexcept {
    fw::net::InstanceDesc d{};
    if (!desc_of(r, &d)) {
        if (out) *out = d;
        return fw::net::kFpUnknown;
    }
    if (out) *out = d;
    return fp_of(r.base_id, d);
}

bool self_check() noexcept {
    // The plain 10mm pistol of the 4a test (template 2, six mods), the same
    // vector net/tests/test_stage4b_instances.py pins.
    fw::net::InstanceDesc d{};
    d.tmpl = 2;
    d.flags = fw::net::kInstanceFlagOie;
    d.health = -1.0f;
    const std::uint32_t mods[6] = {0x91FC4, 0x231AB, 0x100E27, 0x91FC2, 0x148409, 0x4F21D};
    d.mod_n = 6;
    for (int i = 0; i < 6; ++i) { d.mods[i].form = mods[i]; d.mods[i].attach = 0; d.mods[i].rank = 1; }
    const std::uint64_t got = fp_of(0x4822, d);
    constexpr std::uint64_t want = 0x5EC6921B06D17B4Bull;
    if (got != want) {
        FW_ERR("[instance] fingerprint self-check FAILED: 0x%016llX, the server computes "
               "0x%016llX: every instance line would diverge",
               static_cast<unsigned long long>(got), static_cast<unsigned long long>(want));
        return false;
    }
    FW_LOG("[instance] fingerprint self-check OK (0x%016llX, the server's value)",
           static_cast<unsigned long long>(got));
    return true;
}

} // namespace fw::persist::instance
