// L5 stage 4b (2026-10-03) — the instance of a stack, as the wire names it.
//
// A container line was (base, count) until v33: a modded pistol and a plain
// one were the same item, an observer's AddItem rolled an instance of its
// own and a base-only removal took whatever stack sat at the head of the
// chain (all three measured live in 4a). Every line now carries the
// fingerprint of the instance it holds and the descriptor that rebuilds it.
//
// The fingerprint is FNV-1a 64 over the canonical bytes documented in
// net/protocol.h (kFpPlain) and net/protocol.py (instance_fp); this file is
// the DLL's half and checks the shared vector at startup, because the two
// sides disagreeing by one byte would make every line of every container
// diverge forever.

#pragma once

#include <cstdint>

namespace fw::net { struct InstanceDesc; }
namespace fw::persist::inventory { struct StackRecord; }

namespace fw::persist::instance {

// The fingerprint of `d` as an instance of `base`.
std::uint64_t fp_of(std::uint32_t base, const fw::net::InstanceDesc& d) noexcept;

// The descriptor of a decoded stack (the capture's own record). False when
// the record cannot name its instance: more mods than the wire carries, or
// an OIE or Health node the decoder did not believe (its vtable did not
// match). The caller then sends kFpUnknown and no descriptor.
bool desc_of(const fw::persist::inventory::StackRecord& r, fw::net::InstanceDesc* out) noexcept;

// desc_of, then fp_of; kFpUnknown when desc_of says no. `out` may be null.
std::uint64_t fp_of_record(const fw::persist::inventory::StackRecord& r,
                           fw::net::InstanceDesc* out) noexcept;

// The vector net/tests/test_stage4b_instances.py pins. Logs the verdict;
// false means the two implementations disagree and the instance layer must
// not be trusted this session.
bool self_check() noexcept;

} // namespace fw::persist::instance
