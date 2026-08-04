#include "audit.h"

#include <windows.h>

#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <unordered_map>

#include "log.h"
#include "offsets.h"

namespace fw::audit {

namespace {

struct Entry {
    std::uint32_t kinds       = 0;
    std::uint32_t notes       = 0;      // how many times we touched it
    void*         actor       = nullptr;
    // Where it was the FIRST time we touched it, so the dump can show how far
    // our writes have carried it since.
    bool          have_first  = false;
    float         first[3]    = {0, 0, 0};
    std::uint32_t first_cell  = 0;
};

std::mutex                                     g_mtx;
std::unordered_map<std::uint32_t, Entry>       g_ledger;
std::wstring                                   g_path;
std::atomic<std::uint64_t>                     g_dumps{0};

// Live snapshot of one actor, read defensively: the object may already be torn
// down by the time we dump. Anything unreadable comes back as zeroes, which is
// itself a datum worth seeing in the table.
struct Live {
    bool          ok         = false;
    void*         cell       = nullptr;
    std::uint32_t cell_fid   = 0;
    std::uint32_t form_flags = 0;
    float         pos[3]     = {0, 0, 0};
};

Live read_live(void* actor) noexcept {
    Live v{};
    if (!actor) return v;
    __try {
        const auto* p = reinterpret_cast<const std::uint8_t*>(actor);
        v.form_flags = *reinterpret_cast<const std::uint32_t*>(p + 0x10);
        const auto* pos = reinterpret_cast<const float*>(p + fw::offsets::POS_OFF);
        v.pos[0] = pos[0]; v.pos[1] = pos[1]; v.pos[2] = pos[2];
        v.cell = *reinterpret_cast<void* const*>(p + fw::offsets::PARENT_CELL_OFF);
        if (v.cell) {
            v.cell_fid = *reinterpret_cast<const std::uint32_t*>(
                reinterpret_cast<const std::uint8_t*>(v.cell) +
                fw::offsets::FORMID_OFF);
        }
        v.ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        v.ok = false;
    }
    return v;
}

void kinds_to_str(std::uint32_t k, char* out, std::size_t n) {
    std::snprintf(out, n, "%s%s%s%s%s%s%s%s",
                  (k & kBonesPinned)       ? "bones "     : "",
                  (k & kPosApplied)        ? "pos "       : "",
                  (k & kPosAppliedRaw)     ? "posraw "    : "",
                  (k & kTeleported)        ? "TELEPORT "  : "",
                  (k & kStopCombatBlocked) ? "stopblk "   : "",
                  (k & kSkipTickWritten)   ? "skiptick "  : "",
                  (k & kInCombatForced)    ? "incombat "  : "",
                  (k & kHavokKeyframed)    ? "havok "     : "");
}

void write_line(HANDLE h, const char* s) {
    DWORD w = 0;
    WriteFile(h, s, static_cast<DWORD>(std::strlen(s)), &w, nullptr);
}

}  // namespace

void init(const std::wstring& dir) {
    std::lock_guard<std::mutex> lk(g_mtx);
    g_path = dir + L"\\fw_audit.log";
    // Truncate once per process so each session's file stands alone and two
    // deaths inside one run can be diffed against each other.
    HANDLE h = CreateFileW(g_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                           nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    FW_LOG("[audit] mutation ledger armed -> fw_audit.log");
}

void note(std::uint32_t form_id, std::uint32_t kind, void* actor) noexcept {
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return;
    std::lock_guard<std::mutex> lk(g_mtx);
    Entry& e = g_ledger[form_id];
    e.kinds |= kind;
    ++e.notes;
    if (actor) e.actor = actor;
    if (!e.have_first && actor) {
        const Live v = read_live(actor);
        if (v.ok) {
            e.have_first = true;
            e.first[0] = v.pos[0]; e.first[1] = v.pos[1]; e.first[2] = v.pos[2];
            e.first_cell = v.cell_fid;
        }
    }
}

// ---------------------------------------------------------------------------
// Build 69o (2026-08-04) — WRITE RING implementation. See audit.h for the why.

namespace {

struct WRec {
    std::uint64_t dest;       // destination address
    std::uint32_t t_ms;       // ms since ring arm (GetTickCount64 delta)
    std::uint32_t fid;        // form id (0 = unknown)
    std::uint8_t  bytes[16];  // first bytes of the SOURCE data
    std::uint16_t len;        // total bytes the store covered
    std::uint8_t  site;       // WSite
    std::uint8_t  cap;        // valid bytes in bytes[]
    std::uint32_t seq_lo;     // low 32 bits of the claim sequence
};
static_assert(sizeof(WRec) == 40, "WRec layout drifted — fw_writes.bin readers assume 40");

constexpr std::size_t kWCap  = std::size_t{1} << 19;   // 524288 records, 20 MB BSS
constexpr std::size_t kWMask = kWCap - 1;

WRec                        g_wring[kWCap];            // zero-init BSS
std::atomic<std::uint64_t>  g_wseq{0};
std::atomic<std::uint64_t>  g_wsite_count[32]{};       // per-site totals
std::uint64_t               g_wt0 = 0;                 // ring arm tick
std::atomic<bool>           g_wdumped{false};
thread_local std::uint32_t  g_wctx_fid_tls = 0;

const char* wsite_name(std::uint8_t s) noexcept {
    switch (static_cast<WSite>(s)) {
        case WSite::kBone3x3:   return "bone3x3";
        case WSite::kBoneTrans: return "bonetrans";
        case WSite::kNodeXform: return "nodexform";
        case WSite::kGeomXform: return "geomxform";
        case WSite::kSkinPtr:   return "skinptr";
        case WSite::kGhostPos:  return "ghostpos";
        case WSite::kPosRaw:    return "posraw";
        case WSite::kPosRawNif: return "posrawnif";
        case WSite::kGlobalVar: return "globalvar";
        case WSite::kHpFunnel:  return "hpfunnel";
        case WSite::kRefInc:    return "refinc";
        case WSite::kRefDec:    return "refdec";
        case WSite::kNiFree:    return "NIFREE";
        case WSite::kSkipTick:  return "skiptick";
        case WSite::kInCombat:  return "incombat";
        case WSite::kEngSetPos: return "engsetpos";
        case WSite::kEngMoveTo: return "engmoveto";
        case WSite::kEngKill:   return "engkill";
        case WSite::kEngMotion: return "engmotion";
        default:                return "?";
    }
}

}  // namespace

void wctx_fid(std::uint32_t fid) noexcept { g_wctx_fid_tls = fid; }

void wnote(WSite site, const void* dest, const void* src,
           std::uint32_t len, std::uint32_t fid) noexcept {
    if (!dest) return;
    if (g_wt0 == 0) g_wt0 = GetTickCount64();   // benign race: same-ish value
    const std::uint64_t seq = g_wseq.fetch_add(1, std::memory_order_relaxed);
    g_wsite_count[static_cast<std::uint8_t>(site) & 31]
        .fetch_add(1, std::memory_order_relaxed);
    WRec& r = g_wring[seq & kWMask];
    r.dest   = reinterpret_cast<std::uint64_t>(dest);
    r.t_ms   = static_cast<std::uint32_t>(GetTickCount64() - g_wt0);
    r.fid    = fid ? fid : g_wctx_fid_tls;
    r.len    = static_cast<std::uint16_t>(len > 0xFFFF ? 0xFFFF : len);
    r.site   = static_cast<std::uint8_t>(site);
    r.seq_lo = static_cast<std::uint32_t>(seq);
    const std::uint32_t cap = len < 16 ? len : 16;
    r.cap = static_cast<std::uint8_t>(cap);
    if (src && cap) std::memcpy(r.bytes, src, cap);
}

void wring_dump_crash(const void* ctx_v, std::uintptr_t fault_addr) noexcept {
    // First AV wins; later AVs (the VEH caps at 30) would just repeat it.
    bool expected = false;
    if (!g_wdumped.compare_exchange_strong(expected, true)) return;

    const std::uint64_t total = g_wseq.load(std::memory_order_relaxed);
    const std::uint64_t valid = total < kWCap ? total : kWCap;
    const std::uint64_t now_ms = g_wt0 ? (GetTickCount64() - g_wt0) : 0;

    // (1) Raw binary dump next to the audit log: header + the whole ring.
    // Offline analysis can then answer arbitrary "who wrote near X" queries,
    // not just the register-window scan below.
    {
        std::wstring p = g_path;  // ...\fw_audit.log
        const auto slash = p.find_last_of(L'\\');
        p = (slash == std::wstring::npos ? L"" : p.substr(0, slash + 1));
        p += L"fw_writes.bin";
        HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                               nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                               nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            struct {
                char          magic[4];      // "FWWR"
                std::uint32_t version;       // 1
                std::uint32_t entry_size;    // 40
                std::uint32_t capacity;      // kWCap
                std::uint64_t total_seq;     // writes ever recorded
                std::uint64_t now_ms;        // ring-relative crash time
                std::uint64_t fault_addr;
            } hdr{{'F','W','W','R'}, 1, sizeof(WRec),
                  static_cast<std::uint32_t>(kWCap), total, now_ms,
                  static_cast<std::uint64_t>(fault_addr)};
            DWORD w = 0;
            WriteFile(h, &hdr, sizeof(hdr), &w, nullptr);
            WriteFile(h, g_wring, static_cast<DWORD>(sizeof(g_wring)), &w,
                      nullptr);
            CloseHandle(h);
        }
    }

    // (2) Targeted scan: any record overlapping a crash register (± a small
    // window) is printed straight into fw_native.log, so the answer is visible
    // without touching the binary. The overlap window is asymmetric — an
    // object pointer register usually points at the object START, and our
    // write may have landed anywhere inside it.
    struct Probe { const char* name; std::uint64_t v; };
    const CONTEXT* c = static_cast<const CONTEXT*>(ctx_v);
    const Probe probes[] = {
        {"FAULT", static_cast<std::uint64_t>(fault_addr)},
        {"rax", c->Rax}, {"rbx", c->Rbx}, {"rcx", c->Rcx}, {"rdx", c->Rdx},
        {"rsi", c->Rsi}, {"rdi", c->Rdi}, {"rbp", c->Rbp}, {"r8",  c->R8},
        {"r9",  c->R9},  {"r10", c->R10}, {"r11", c->R11}, {"r12", c->R12},
        {"r13", c->R13}, {"r14", c->R14}, {"r15", c->R15},
    };

    char sites[512]; std::size_t sn = 0;
    for (int i = 0; i < 32 && sn + 32 < sizeof(sites); ++i) {
        const auto cnt = g_wsite_count[i].load(std::memory_order_relaxed);
        if (!cnt) continue;
        sn += std::snprintf(sites + sn, sizeof(sites) - sn, "%s=%llu ",
                            wsite_name(static_cast<std::uint8_t>(i)),
                            static_cast<unsigned long long>(cnt));
    }
    FW_ERR("[audit-w] ring at crash: %llu writes total, %llu in ring "
           "(oldest %.1fs ago) — %s",
           static_cast<unsigned long long>(total),
           static_cast<unsigned long long>(valid),
           valid ? (now_ms - g_wring[(total - valid) & kWMask].t_ms) / 1000.0
                 : 0.0, sites);

    int hits = 0;
    for (std::uint64_t k = 0; k < valid && hits < 48; ++k) {
        const WRec& r = g_wring[(total - 1 - k) & kWMask];  // newest first
        for (const Probe& pb : probes) {
            if (!pb.v) continue;
            // overlap of [dest, dest+len) with [probe-0x20, probe+0x48)
            if (r.dest + r.len <= pb.v - 0x20 || r.dest >= pb.v + 0x48)
                continue;
            char hex[3 * 16 + 1]; std::size_t hn = 0;
            for (int b = 0; b < r.cap; ++b)
                hn += std::snprintf(hex + hn, sizeof(hex) - hn, "%02X ",
                                    r.bytes[b]);
            if (!hn) hex[0] = '\0';
            FW_ERR("[audit-w] HIT %s(0x%llX): site=%s dest=0x%llX len=%u "
                   "fid=0x%08X age=%.3fs bytes= %s",
                   pb.name, static_cast<unsigned long long>(pb.v),
                   wsite_name(r.site),
                   static_cast<unsigned long long>(r.dest), r.len, r.fid,
                   (now_ms - r.t_ms) / 1000.0, hex);
            ++hits;
            break;   // one probe match per record is enough
        }
    }
    FW_ERR("[audit-w] targeted scan done: %d hit(s); full ring in "
           "fw_writes.bin", hits);
}

void dump(const char* reason) noexcept {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (g_path.empty()) return;

    HANDLE h = CreateFileW(g_path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;

    const auto n = g_dumps.fetch_add(1, std::memory_order_relaxed) + 1;
    char buf[640];

    SYSTEMTIME st{};
    GetLocalTime(&st);
    std::snprintf(buf, sizeof(buf),
        "\r\n=== DUMP #%llu  %02u:%02u:%02u.%03u  reason=%s  tracked=%zu ===\r\n"
        "  The crash branch in TESObjectCELL::DetachReference runs ONLY for refs\r\n"
        "  with flags&0x4000==0 (not temporary) AND flags&0x400==0 (not persistent).\r\n"
        "  'moved' is the distance from where we FIRST saw the actor to where it is\r\n"
        "  now; a large value with an unchanged cell is the incoherence we suspect.\r\n"
        "%-10s %-9s %-9s %-8s %-10s %-9s %s\r\n",
        static_cast<unsigned long long>(n),
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        reason ? reason : "?", g_ledger.size(),
        "fid", "cell_now", "cell_1st", "flags", "moved", "touches", "what-we-did");
    write_line(h, buf);

    std::size_t risky = 0;
    for (const auto& kv : g_ledger) {
        const Entry& e = kv.second;
        const Live v = read_live(e.actor);

        double moved = -1.0;
        if (v.ok && e.have_first) {
            const double dx = v.pos[0] - e.first[0];
            const double dy = v.pos[1] - e.first[1];
            const double dz = v.pos[2] - e.first[2];
            moved = std::sqrt(dx * dx + dy * dy + dz * dz);
        }
        // Would this ref reach the faulting vcall if the engine detached it now?
        const bool in_branch = v.ok
            && (v.form_flags & 0x4000u) == 0
            && (v.form_flags & 0x400u) == 0;
        if (in_branch) ++risky;

        char what[128];
        kinds_to_str(e.kinds, what, sizeof(what));

        if (!v.ok) {
            std::snprintf(buf, sizeof(buf),
                "0x%08X %-9s %-9s %-8s %-10s %-9u %s\r\n",
                kv.first, "UNREADABLE", "-", "-", "-", e.notes, what);
        } else {
            char movedbuf[24];
            if (moved < 0) std::snprintf(movedbuf, sizeof(movedbuf), "?");
            else           std::snprintf(movedbuf, sizeof(movedbuf), "%.0f", moved);
            std::snprintf(buf, sizeof(buf),
                "0x%08X 0x%07X 0x%07X 0x%06X %-10s %-9u %s%s\r\n",
                kv.first, v.cell_fid, e.first_cell, v.form_flags,
                movedbuf, e.notes, what,
                in_branch ? " <<DETACH-BRANCH" : "");
        }
        write_line(h, buf);
    }

    std::snprintf(buf, sizeof(buf),
        "  %zu of %zu recorded actors would enter the faulting detach branch.\r\n",
        risky, g_ledger.size());
    write_line(h, buf);
    CloseHandle(h);

    FW_LOG("[audit] dump #%llu written (%zu actors, %zu in the detach branch) "
           "-> fw_audit.log", static_cast<unsigned long long>(n),
           g_ledger.size(), risky);
}

}  // namespace fw::audit
