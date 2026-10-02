#include "checkpoint.h"

#include <windows.h>
#include <bcrypt.h>
#include <shlobj.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

#include "../config.h"
#include "../engine/engine_calls.h"   // get_pc_parent_cell
#include "../log.h"
#include "../native/scene_inject.h"   // ghost_scene_settled
#include "../native/world_spawn.h"    // the world manifest: snapshot and purge
#include "../net/client.h"            // enqueue_ckpt_done
#include "../net/protocol.h"          // the codes and the payload
#include "../offsets.h"
#include "../hooks/npc_ai_suppress.h" // in_local_death_standdown
#include "custody.h"                  // L5 stage 3b: the transport of the bytes
#include "death.h"                    // respawn_in_progress
#include "inventory_capture.h"
#include "lifecycle.h"

namespace fw::persist::checkpoint {

namespace {

// From the console's SaveGame handler sub_1405EF9B0 (decomp, 2026-09-27):
//   if (sub_141084830(save_device, nullptr)) {   // device check, always 1 on PC
//       sub_140BFE3C0(mgr);                       // render capture for the header
//       sub_140BF8E10(mgr, name, -1, 0, 1);       // the named save, zlib on
//   }
using DeviceCheckFn   = char (__fastcall*)(void* device, void* callback);
using RenderCaptureFn = std::int64_t (__fastcall*)(void* mgr);
using NamedSaveFn     = std::int64_t (__fastcall*)(void* mgr, const char* name,
                                                   std::uint32_t a3, int a4, std::uint8_t a5);
using SaveGateFn      = bool (__fastcall*)(void* mgr);

// The pending request: one at a time, the newest wins. Written by the net
// thread (the server's request) or any thread (the test key), read and
// cleared by the main thread at the save point.
std::mutex    g_req_mx;
bool          g_req_pending = false;
std::uint32_t g_req_seq = 0;
std::uint8_t  g_req_reason = fw::net::kCkptReasonTest;
int           g_req_deadline_frames = 300;
int           g_req_waited = 0;
char          g_req_why[32] = "";

std::uint32_t  g_local_seq = 0;      // checkpoints attempted this session (the manifest number)
std::wstring   g_dir;
std::string    g_client_id;
std::string    g_genesis;
std::uintptr_t g_base = 0;
bool g_test_enabled = false;         // inventory_capture: the F10 key and the manifest for the diff
bool g_enabled = false;              // persist_lifecycle: the grant machinery is armed
constexpr std::size_t kKeep = 3;     // checkpoints kept on disk per identity

std::uintptr_t module_base() noexcept {
    if (!g_base) g_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(L"Fallout4.exe"));
    return g_base;
}

std::uint64_t wall_ms() noexcept {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    const std::uint64_t t = (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    return (t - 116444736000000000ull) / 10000ull;
}

bool seh_device_ok(std::uintptr_t base) noexcept {
    __try {
        void* device = *reinterpret_cast<void**>(base + offsets::SAVE_DEV_SINGLETON_RVA);
        if (!device) return false;
        return reinterpret_cast<DeviceCheckFn>(base + offsets::LOAD_PRECOND_FN_RVA)(device, nullptr) != 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

bool seh_gate(std::uintptr_t base, void* mgr) noexcept {
    __try { return reinterpret_cast<SaveGateFn>(base + offsets::SAVE_GATE_RVA)(mgr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

bool seh_render_capture(std::uintptr_t base, void* mgr) noexcept {
    __try { reinterpret_cast<RenderCaptureFn>(base + offsets::SAVELOAD_RENDER_CAPTURE_RVA)(mgr); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// The named save under a grant. SEH and the RAII grant cannot share a
// frame (C2712), hence the two functions.
std::int64_t seh_named_save(std::uintptr_t base, void* mgr, const char* name) noexcept {
    __try {
        return reinterpret_cast<NamedSaveFn>(base + offsets::SAVE_NAMED_RVA)(
            mgr, name, 0xFFFFFFFFu, 0, 1);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
}
std::int64_t granted_named_save(std::uintptr_t base, void* mgr, const char* name) {
    fw::persist::SaveGrant grant;
    return seh_named_save(base, mgr, name);
}

// %USERPROFILE%\Documents\My Games\Fallout4\Saves\, the default save folder
// (sLocalSavePath is "Saves\" unless the INI moved it).
std::wstring saves_dir() {
    wchar_t docs[MAX_PATH] = L"";
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_PERSONAL, nullptr, SHGFP_TYPE_CURRENT, docs))) return L"";
    std::wstring p(docs);
    p += L"\\My Games\\Fallout4\\Saves\\";
    return p;
}

std::wstring widen(const char* s) {
    std::wstring w;
    for (const char* c = s; c && *c; ++c) w += static_cast<wchar_t>(static_cast<unsigned char>(*c));
    return w;
}

std::wstring expected_save_path(const char* name) {
    std::wstring p = saves_dir();
    if (p.empty()) return p;
    p += widen(name);
    p += L".fos";
    return p;
}

// SHA-256 of a file through CNG, 1 MB at a time. `size_out` = bytes hashed.
// False on any failure (a missing file included).
bool sha256_file(const wchar_t* path, std::uint8_t out[32], std::uint64_t* size_out) {
    if (size_out) *size_out = 0;
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    BCRYPT_ALG_HANDLE  alg  = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = false;
    std::uint64_t total = 0;
    std::vector<std::uint8_t> buf(1u << 20);
    if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0))
            && BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0))) {
        ok = true;
        for (;;) {
            DWORD n = 0;
            if (!ReadFile(f, buf.data(), static_cast<DWORD>(buf.size()), &n, nullptr)) { ok = false; break; }
            if (n == 0) break;
            if (!BCRYPT_SUCCESS(BCryptHashData(hash, buf.data(), n, 0))) { ok = false; break; }
            total += n;
        }
        if (ok && !BCRYPT_SUCCESS(BCryptFinishHash(hash, out, 32, 0))) ok = false;
    }
    if (hash) BCryptDestroyHash(hash);
    if (alg)  BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(f);
    if (size_out) *size_out = total;
    return ok;
}

// "fwck_<client id>_<yyyymmdd>_<hhmmss>": the identity in the name keeps two
// clients on one machine (one Saves folder) apart, the timestamp sorts.
void make_name(char* out, std::size_t n) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    std::snprintf(out, n, "fwck_%s_%04u%02u%02u_%02u%02u%02u", g_client_id.c_str(),
                  unsigned(st.wYear), unsigned(st.wMonth), unsigned(st.wDay),
                  unsigned(st.wHour), unsigned(st.wMinute), unsigned(st.wSecond));
}

// The last kKeep checkpoints of this identity stay, older ones go (the
// engine's own save rotation does not know named saves).
void keep_last() {
    const std::wstring dir = saves_dir();
    if (dir.empty()) return;
    std::wstring pattern = dir + L"fwck_" + widen(g_client_id.c_str()) + L"_*.fos";
    std::vector<std::wstring> names;
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) names.emplace_back(fd.cFileName);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    std::sort(names.begin(), names.end(), std::greater<std::wstring>());   // newest first
    for (std::size_t i = kKeep; i < names.size(); ++i) {
        const std::wstring p = dir + names[i];
        const bool gone = DeleteFileW(p.c_str()) != 0;
        std::wstring co = p;
        if (co.size() > 4) { co.replace(co.size() - 4, 4, L".f4se"); DeleteFileW(co.c_str()); }
        FW_LOG("[ckpt] old checkpoint %ls %s", names[i].c_str(), gone ? "deleted" : "NOT deleted");
    }
}

// The world manifest of a checkpoint: "<game dir>\fw_world_<name>.txt",
// one line per object of ours in that save (fid, base, wid, position). The
// game directory and not the Saves folder: the two test clients share the
// latter, and this file belongs to the process that wrote the save.
std::wstring world_manifest_path(const char* name) {
    std::wstring p = g_dir;
    p += L"\\fw_world_";
    p += widen(name);
    p += L".txt";
    return p;
}

constexpr std::size_t kWorldManifestCap = 512;

void rotate_world_manifests() {
    const std::wstring dir = g_dir + L"\\";
    const std::wstring pattern = dir + L"fw_world_fwck_" + widen(g_client_id.c_str()) + L"_*.txt";
    std::vector<std::wstring> names;
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) names.emplace_back(fd.cFileName);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    std::sort(names.begin(), names.end(), std::greater<std::wstring>());   // newest first
    for (std::size_t i = kKeep; i < names.size(); ++i) {
        const std::wstring p = dir + names[i];
        DeleteFileW(p.c_str());
    }
}

// Written right after the save, same frame, same thread: what the save
// carries of ours is what is bound at this instant.
void write_world_manifest(const char* name) {
    static fw::native::world_spawn::WorldObjectStamp stamps[kWorldManifestCap];   // main thread only
    const std::size_t n = fw::native::world_spawn::snapshot_world_objects(stamps, kWorldManifestCap);
    const std::wstring path = world_manifest_path(name);
    FILE* f = _wfopen(path.c_str(), L"wb");
    if (!f) {
        FW_WRN("[ckpt] world manifest %ls NOT written (errno %d): the copies of our objects "
               "in this save cannot be purged at its next load", path.c_str(), errno);
        return;
    }
    std::fprintf(f, "# fwworld 1 %s\n", name);
    for (std::size_t i = 0; i < n; ++i) {
        std::fprintf(f, "%08X %08X %u %.2f %.2f %.2f\n", stamps[i].fid, stamps[i].base_id,
                     stamps[i].wid, stamps[i].pos[0], stamps[i].pos[1], stamps[i].pos[2]);
    }
    std::fclose(f);
    FW_LOG("[ckpt] world manifest fw_world_%s.txt: %zu object(s) of ours in this save "
           "(their copies are purged at its next load)", name, n);
    rotate_world_manifests();
}

struct Outcome {
    std::uint8_t  status = fw::net::kCkptStatusRefused;
    char          name[fw::net::kCkptNameLen] = {};
    std::uint8_t  sha[32] = {};
    std::uint32_t size = 0;
    std::uint64_t digest = 0;
    std::uint32_t digest_seq = 0;
    const char*   why = "";
};

bool seh_player_in_combat(std::uintptr_t base) noexcept {
    __try {
        const std::uint8_t* player = *reinterpret_cast<std::uint8_t* const*>(base + offsets::PLAYER_SINGLETON_RVA);
        if (!player) return false;
        return (player[offsets::PLAYER_IN_COMBAT_FLAG_OFF] & 2) != 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// The gates that make a moment quiet. The commanded path tries again next
// frame while they are closed; the exit path (`leaving`) reports what it
// finds, and skips the three that only postpone: a player leaving in a
// fight still gets a checkpoint. The three exist because of the first live
// death (2026-09-28 20:21): a periodic checkpoint written in the middle of
// a fight became the death reload's target, and put the player back into
// the fight it had just lost.
//
// L5 stage 3d (2026-09-30) — `combat_ok`: a checkpoint the server demanded
// (reason 1) because the character changed in a way the last one contradicts
// (the player left their power armour: a death or a boot from the old one
// would put them back inside it). It is written in a fight too: the respawn
// of stage 3d moves the checkpoint's position to the respawn point, and the
// position is what the combat gate protects.
bool gates_open(void* mgr, std::uintptr_t base, const char** why, bool leaving,
                bool combat_ok = false) {
    if (fw::engine::get_pc_parent_cell() == nullptr) { *why = "no world"; return false; }
    if (!fw::native::ghost_scene_settled())          { *why = "scene not settled"; return false; }
    if (fw::persist::load_in_flight())                { *why = "load in flight"; return false; }
    if (!leaving) {
        if (fw::hooks::in_local_death_standdown())     { *why = "the death stand-down is open"; return false; }
        if (fw::persist::death::respawn_in_progress()) { *why = "a respawn is in progress"; return false; }
        if (!combat_ok && seh_player_in_combat(base))  { *why = "the player is in combat"; return false; }
    }
    if (!seh_gate(base, mgr))                         { *why = "the engine's save gate says no"; return false; }
    return true;
}

// One checkpoint, now: the manifest and its digest (when the capture is
// on), the device, the render capture, the named save under a grant, the
// hash of the file as written, the rotation. Main thread, at a save point.
void write_checkpoint(void* mgr, std::uintptr_t base, Outcome* o) {
    const std::uint32_t local = ++g_local_seq;
    make_name(o->name, sizeof(o->name));
    if (g_test_enabled && fw::persist::inventory::capture_now(base, "checkpoint")) {
        const auto& m = fw::persist::inventory::last();
        if (m.complete) {
            o->digest     = m.digest;
            o->digest_seq = m.seq;
            // The digest of THIS manifest goes to the server with the save:
            // the record a checkpoint is held against.
            fw::persist::inventory::send_digest_now(fw::net::kInvDigestWhyCheckpoint);
            wchar_t json_path[MAX_PATH];
            _snwprintf_s(json_path, MAX_PATH, _TRUNCATE, L"%s\\fw_inventory_ckpt_%u.json",
                         g_dir.c_str(), local);
            (void)fw::persist::inventory::dump_json(json_path);
        }
    }
    if (!seh_device_ok(base)) {
        o->status = fw::net::kCkptStatusNoDevice;
        o->why = "save device not available";
        return;
    }
    seh_render_capture(base, mgr);
    const std::int64_t rc = granted_named_save(base, mgr, o->name);
    const std::wstring path = expected_save_path(o->name);
    std::uint64_t size = 0;
    const bool hashed = !path.empty() && sha256_file(path.c_str(), o->sha, &size);
    if (rc == 0 || !hashed || size == 0) {
        o->status = fw::net::kCkptStatusSaveFailed;
        o->why = (rc == 0) ? "the named save returned 0" : "the file did not appear on disk";
        return;
    }
    o->size   = static_cast<std::uint32_t>(size > 0xFFFFFFFFull ? 0xFFFFFFFFull : size);
    o->status = fw::net::kCkptStatusOk;
    keep_last();
    write_world_manifest(o->name);
}

const char* reason_name(std::uint8_t r) noexcept {
    switch (r) {
    case fw::net::kCkptReasonPeriodic: return "periodic";
    case fw::net::kCkptReasonDemand:   return "on demand";
    case fw::net::kCkptReasonExit:     return "exit";
    case fw::net::kCkptReasonTest:     return "test key";
    default: return "?";
    }
}

// CKPT_DONE to the server and the line in the log. `immediate` sends it on
// this thread first (the window close: the goodbye follows at once).
void report(const Outcome& o, std::uint32_t seq, std::uint8_t reason, int waited,
            bool immediate = false) {
    fw::net::CkptDonePayload p{};
    p.seq    = seq;
    p.status = o.status;
    std::memcpy(p.name, o.name, sizeof(p.name));
    std::memcpy(p.sha256, o.sha, sizeof(p.sha256));
    p.size       = o.size;
    p.digest     = o.digest;
    p.digest_seq = o.digest_seq;
    p.wall_ms    = wall_ms();
    if (immediate) fw::net::client().send_ckpt_done_now(p);
    fw::net::client().enqueue_ckpt_done(p);
    if (o.status == fw::net::kCkptStatusOk) {
        char hex[17];
        for (int i = 0; i < 8; ++i) std::snprintf(hex + 2 * i, 3, "%02X", o.sha[i]);
        FW_LOG("[ckpt] '%s' WRITTEN (%s, seq %u): %u bytes, sha256 %s..., digest %016llX "
               "(capture #%u), after %d frame(s) -> CKPT_DONE sent. Diff: python "
               "tools/fos_inventory.py \"<Saves>\\%s.fos\" --diff \"<game dir>\\fw_inventory_ckpt_%u.json\"",
               o.name, reason_name(reason), seq, o.size, hex,
               static_cast<unsigned long long>(o.digest), o.digest_seq, waited, o.name, g_local_seq);
        // L5 stage 3b — the bytes follow the report to the server (a worker
        // thread; the exit paths wait for it a few seconds at most).
        fw::persist::custody::enqueue_upload(o.name, o.sha, o.size,
                                             expected_save_path(o.name).c_str(),
                                             world_manifest_path(o.name).c_str());
    } else {
        FW_WRN("[ckpt] checkpoint (%s, seq %u) NOT written: %s -> CKPT_DONE status %u sent",
               reason_name(reason), seq, o.why, unsigned(o.status));
    }
}

void set_request(std::uint32_t seq, std::uint8_t reason, int deadline_frames, const char* why) {
    std::lock_guard<std::mutex> lk(g_req_mx);
    g_req_pending = true;
    g_req_seq = seq;
    g_req_reason = reason;
    g_req_deadline_frames = deadline_frames;
    g_req_waited = 0;
    std::snprintf(g_req_why, sizeof(g_req_why), "%s", why ? why : "?");
}

} // namespace

void configure(const fw::config::Settings& cfg, const wchar_t* output_dir) {
    g_test_enabled = cfg.inventory_capture;
    g_enabled      = cfg.persist_lifecycle;
    g_dir          = output_dir ? output_dir : L"";
    g_client_id    = cfg.client_id;
    g_genesis      = cfg.auto_load_save;
    if (!g_enabled) {
        FW_LOG("[ckpt] commanded checkpoints OFF (persist_lifecycle=false): no save can be granted");
        return;
    }
    FW_LOG("[ckpt] commanded checkpoints armed: names fwck_%s_<date>_<time>, the last %zu kept",
           g_client_id.c_str(), kKeep);
    if (cfg.checkpoint_test_key) {
        FW_LOG("[ckpt] test checkpoint armed on virtual-key 0x%02X (a granted named "
               "save + the inventory manifest, for tools/fos_inventory.py --diff)",
               cfg.checkpoint_test_key);
    }
}

void request_test(const char* why) {
    if (!g_enabled || !g_test_enabled) {
        FW_LOG("[ckpt] test request (%s) ignored: %s", why ? why : "?",
               !g_enabled ? "persist_lifecycle=false" : "inventory_capture=false");
        return;
    }
    set_request(0, fw::net::kCkptReasonTest, 300, why);
    FW_LOG("[ckpt] test checkpoint requested (%s): served at the engine's save point "
           "when the gates open", why ? why : "?");
}

void request_commanded(std::uint32_t seq, std::uint8_t reason, std::uint16_t deadline_s) {
    if (!g_enabled) {
        Outcome o;
        o.status = fw::net::kCkptStatusRefused;
        o.why = "persist_lifecycle=false";
        report(o, seq, reason, 0);
        return;
    }
    int frames = static_cast<int>(deadline_s) * 60;
    if (frames < 60) frames = 60;
    if (frames > 7200) frames = 7200;
    set_request(seq, reason, frames, "server");
    FW_LOG("[ckpt] checkpoint requested by the server (seq %u, %s, %u s): served at the "
           "engine's save point when the gates open", seq, reason_name(reason), unsigned(deadline_s));
}

static void run_now_impl(void* mgr, std::uint8_t reason, bool immediate) {
    if (!g_enabled || !mgr) return;
    if (!fw::net::client().is_connected()) {
        FW_LOG("[ckpt] checkpoint (%s) skipped: no session to report it to", reason_name(reason));
        return;
    }
    const std::uintptr_t base = module_base();
    const char* why = "";
    Outcome o;
    if (!gates_open(mgr, base, &why, /*leaving=*/true)) {
        o.status = fw::net::kCkptStatusDeferred;
        o.why = why;
    } else {
        write_checkpoint(mgr, base, &o);
    }
    report(o, 0, reason, 0, immediate);
}

void run_now(void* mgr, std::uint8_t reason) {
    run_now_impl(mgr, reason, /*immediate=*/false);
}

static void* seh_save_load_mgr(std::uintptr_t base) noexcept {
    __try { return *reinterpret_cast<void**>(base + offsets::SAVE_LOAD_MGR_SINGLETON_RVA); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

void run_now_here(std::uint8_t reason, bool immediate) {
    if (!g_enabled) return;
    void* mgr = seh_save_load_mgr(module_base());
    if (!mgr) {
        FW_WRN("[ckpt] checkpoint (%s) skipped: the save manager singleton is null",
               reason_name(reason));
        return;
    }
    run_now_impl(mgr, reason, immediate);
}

void run_pending(void* mgr) {
    if (!mgr || !g_enabled) return;
    std::uint32_t seq = 0;
    std::uint8_t reason = 0;
    int deadline = 0, waited = 0;
    {
        std::lock_guard<std::mutex> lk(g_req_mx);
        if (!g_req_pending) return;
        seq = g_req_seq; reason = g_req_reason; deadline = g_req_deadline_frames;
        waited = ++g_req_waited;
    }
    const std::uintptr_t base = module_base();
    const char* why = "";
    if (!gates_open(mgr, base, &why, /*leaving=*/false,
                    /*combat_ok=*/reason == fw::net::kCkptReasonDemand)) {
        if (waited == 1 || waited % 300 == 0) {
            FW_LOG("[ckpt] request (%s, seq %u) waiting: %s (%d/%d frames)",
                   reason_name(reason), seq, why, waited, deadline);
        }
        if (waited >= deadline) {
            {
                std::lock_guard<std::mutex> lk(g_req_mx);
                if (g_req_seq == seq) g_req_pending = false;
            }
            Outcome o;
            o.status = fw::net::kCkptStatusDeferred;
            o.why = why;
            report(o, seq, reason, waited);
        }
        return;
    }
    {
        std::lock_guard<std::mutex> lk(g_req_mx);
        if (g_req_seq == seq) g_req_pending = false;
    }
    Outcome o;
    write_checkpoint(mgr, base, &o);
    report(o, seq, reason, waited);
}

void note_load_request(const char* name) {
    using fw::native::world_spawn::WorldObjectStamp;
    if (!name || std::strncmp(name, "fwck_", 5) != 0) {
        fw::native::world_spawn::purge_saved_copies(nullptr, 0, name ? name : "");
        return;
    }
    const std::wstring path = world_manifest_path(name);
    FILE* f = _wfopen(path.c_str(), L"rb");
    if (!f) {
        FW_LOG("[ckpt] no world manifest for '%s' (%ls): the copies of our objects in that "
               "save, if any, stay", name, path.c_str());
        fw::native::world_spawn::purge_saved_copies(nullptr, 0, name);
        return;
    }
    std::vector<WorldObjectStamp> stamps;
    char line[256];
    while (std::fgets(line, sizeof(line), f)) {
        if (line[0] == '#') continue;
        WorldObjectStamp s{};
        unsigned fid = 0, base = 0, wid = 0;
        if (std::sscanf(line, "%x %x %u %f %f %f", &fid, &base, &wid,
                        &s.pos[0], &s.pos[1], &s.pos[2]) != 6) continue;
        s.fid = fid; s.base_id = base; s.wid = wid;
        if (s.fid == 0) continue;
        stamps.push_back(s);
        if (stamps.size() >= kWorldManifestCap) break;
    }
    std::fclose(f);
    FW_LOG("[ckpt] world manifest of '%s': %zu object(s) of ours were in that save",
           name, stamps.size());
    fw::native::world_spawn::purge_saved_copies(stamps.empty() ? nullptr : stamps.data(),
                                                stamps.size(), name);
}

void note_custody_word(std::uint16_t bulk_port, const std::uint8_t token[32],
                       const fw::net::CkptCandidate* candidates, std::size_t n) {
    fw::persist::custody::set_word(bulk_port, token);
    if (bulk_port == 0) {
        FW_LOG("[ckpt] the server keeps no custody of checkpoints: they stay on this disk");
        return;
    }
    std::size_t held = 0, queued = 0;
    for (std::size_t i = 0; i < n && candidates; ++i) {
        const fw::net::CkptCandidate& c = candidates[i];
        char name[fw::net::kCkptNameLen];
        std::memcpy(name, c.name, sizeof(name));
        name[sizeof(name) - 1] = '\0';
        if (!name[0]) continue;
        if (c.custody) { ++held; continue; }
        char why[96] = "";
        if (verify_file(name, c.sha256, c.size, why, sizeof(why)) != 0) {
            FW_LOG("[ckpt] '%s' is neither in the server's custody nor usable on this disk (%s)",
                   name, why);
            continue;
        }
        fw::persist::custody::enqueue_upload(name, c.sha256, c.size,
                                             expected_save_path(name).c_str(),
                                             world_manifest_path(name).c_str());
        ++queued;
    }
    FW_LOG("[ckpt] custody word: bulk port %u, %zu candidate(s), %zu in custody, %zu uploaded "
           "now from this disk", unsigned(bulk_port), n, held, queued);
}

int fetch_from_custody(const char* name, const std::uint8_t sha256[32], std::uint32_t size,
                       char* why, std::size_t why_len) {
    if (why && why_len) why[0] = '\0';
    if (!name || !*name) { if (why) std::snprintf(why, why_len, "no name"); return 3; }
    const std::wstring fos = expected_save_path(name);
    if (fos.empty()) { if (why) std::snprintf(why, why_len, "no Saves folder"); return 3; }
    const std::wstring part = fos + L".part";
    const ULONGLONG t0 = GetTickCount64();
    const int rc = fw::persist::custody::fetch(name, sha256, size, part.c_str(),
                                               world_manifest_path(name).c_str(), why, why_len);
    if (rc != 0) {
        DeleteFileW(part.c_str());
        return rc;
    }
    std::uint8_t got[32] = {};
    std::uint64_t gsize = 0;
    if (!sha256_file(part.c_str(), got, &gsize) || gsize != size || std::memcmp(got, sha256, 32) != 0) {
        DeleteFileW(part.c_str());
        if (why) std::snprintf(why, why_len, "the fetched bytes differ from the record");
        return 4;
    }
    if (!MoveFileExW(part.c_str(), fos.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        const DWORD e = GetLastError();
        DeleteFileW(part.c_str());
        if (why) std::snprintf(why, why_len, "the fetched save could not be put in Saves (error %lu)", e);
        return 3;
    }
    FW_LOG("[ckpt] '%s' fetched from the server's custody: %u bytes, sha256 matches the record, "
           "%u ms", name, size, unsigned(GetTickCount64() - t0));
    return 0;
}

bool wait_uploads(unsigned ms) {
    return fw::persist::custody::wait_idle(ms);
}

int verify_file(const char* name, const std::uint8_t sha256[32], std::uint32_t size,
                char* why, std::size_t why_len) {
    if (why && why_len) why[0] = '\0';
    if (!name || !*name) { if (why) std::snprintf(why, why_len, "no name"); return 2; }
    const std::wstring path = expected_save_path(name);
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (path.empty() || !GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) {
        if (why) std::snprintf(why, why_len, "the file is not in Saves");
        return 2;
    }
    std::uint8_t sha[32] = {};
    std::uint64_t got = 0;
    if (!sha256_file(path.c_str(), sha, &got)) {
        if (why) std::snprintf(why, why_len, "the file could not be read");
        return 2;
    }
    if (got != size) {
        if (why) std::snprintf(why, why_len, "size %llu on disk, %u on record",
                               static_cast<unsigned long long>(got), size);
        return 3;
    }
    if (std::memcmp(sha, sha256, 32) != 0) {
        if (why) std::snprintf(why, why_len, "sha256 differs from the record");
        return 3;
    }
    return 0;
}

} // namespace fw::persist::checkpoint
