// FoM-lite native launcher — pragmatic B2 MVP.
//
// Drop-in replacement for `launcher/start_A.bat` / `start_B.bat`. Runs the
// existing Python launcher (launcher/main.py) as a subprocess after locating
// python.exe on PATH and chdir'ing to the repo root. This keeps the complex
// orchestration logic (server mgmt, INI mgmt, fw_config write, PID detect)
// in one place (Python) while giving us a distributable .exe entry point.
//
// Full native port of the Python launcher is deferred — too much scope for
// the value delivered. The pre-main DLL inject we actually need for FoM-lite
// is already handled by the dxgi.dll proxy, so this launcher just needs to
// get FO4 started with the right env.
//
// Build: fw_launcher/build.bat (vcvars64 + cmake + ninja).
// Deploy: fw_launcher/deploy.bat copies to repo root as FoM.exe.
//
// Usage:
//   FoM.exe --side A      # Steam + f4se_loader
//   FoM.exe --side B      # FO4_b + coldclient_loader
//   FoM.exe               # prompts for side
//
// Exit codes:
//   0 = Python launcher exited cleanly
//   1 = bad argv / missing python.exe
//   2 = CreateProcess failed / python invocation failed
//   >=10 = forwarded from python launcher

#include <windows.h>   // WIN32_LEAN_AND_MEAN + NOMINMAX come via CMake

#include <cctype>
#include <clocale>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <string>

namespace {

// Resolve python.exe via SearchPath (uses %PATH%). Returns empty on fail.
std::wstring find_python() {
    wchar_t buf[MAX_PATH] = {};
    const DWORD n = SearchPathW(nullptr, L"python.exe", nullptr,
                                MAX_PATH, buf, nullptr);
    if (n == 0 || n >= MAX_PATH) return L"";
    return std::wstring(buf, n);
}

// Get the directory of our own exe (repo root after deploy).
std::wstring get_exe_dir() {
    wchar_t buf[MAX_PATH] = {};
    const DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L"";
    std::wstring s(buf, n);
    const auto slash = s.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return L".";
    return s.substr(0, slash);
}

// Read a line from stdin (with prompt), trim whitespace, return uppercased
// first char or 0.
char prompt_side() {
    std::wprintf(L"Which side? [A] Steam  [B] FO4_b  : ");
    std::fflush(stdout);
    char line[64] = {};
    if (!std::fgets(line, sizeof(line), stdin)) return 0;
    for (char& c : line) {
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') { c = 0; break; }
    }
    return static_cast<char>(std::toupper(static_cast<unsigned char>(line[0])));
}

// Parse --side from argv.
// Returns:
//   'A' / 'B' if valid --side given
//   0         if --side not present (fall through to prompt)
//  '!' (0x21) if --side is present but malformed (immediate error — no prompt)
// Build 69 — external-launcher mode. Returns the value of `--connect
// <host:port>`, or an empty string if absent.
//
// When present we must NOT prompt for a side: the launcher spawns us
// non-interactively and reads our stdout, so a prompt would hang forever
// waiting on a stdin nobody is attached to. --side stays available (the
// two-instance local test still needs it) but defaults to A.
std::wstring parse_connect(int argc, wchar_t** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::wcscmp(argv[i], L"--connect") == 0) {
            if ((i + 1) >= argc) return L"";
            return std::wstring(argv[i + 1]);
        }
    }
    return L"";
}

// Generic "--flag value" scan for the v19 auth passthrough (--auth, --name).
// We forward these verbatim to the python launcher; validation happens there
// and in the DLL's config parser — duplicating it here would just create a
// third place for the format to drift.
// Presence test for a valueless switch (e.g. --no-mirror-suppress). Kept
// separate from parse_value_flag because a boolean flag has no argument to
// consume — treating it as one would swallow the next real option.
bool has_flag(int argc, wchar_t** argv, const wchar_t* flag) {
    for (int i = 1; i < argc; ++i) {
        if (std::wcscmp(argv[i], flag) == 0) return true;
    }
    return false;
}

std::wstring parse_value_flag(int argc, wchar_t** argv, const wchar_t* flag) {
    for (int i = 1; i < argc; ++i) {
        if (std::wcscmp(argv[i], flag) == 0) {
            if ((i + 1) >= argc) return L"";
            return std::wstring(argv[i + 1]);
        }
    }
    return L"";
}

char parse_side(int argc, wchar_t** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::wcscmp(argv[i], L"--side") == 0) {
            if ((i + 1) >= argc) return '!';
            const wchar_t* v = argv[i + 1];
            if (std::wcslen(v) == 1) {
                const wchar_t c = v[0];
                if (c == L'A' || c == L'a') return 'A';
                if (c == L'B' || c == L'b') return 'B';
            }
            return '!';
        }
    }
    return 0;
}

// Small helper: quote a wstring for inclusion in a CreateProcess cmdline.
// We use the naive rule (wrap with double quotes, escape backslashes and
// internal quotes) which is sufficient for the arguments we pass.
std::wstring shell_quote(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size() + 2);
    out.push_back(L'"');
    for (wchar_t c : s) {
        if (c == L'"' || c == L'\\') out.push_back(L'\\');
        out.push_back(c);
    }
    out.push_back(L'"');
    return out;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    std::setlocale(LC_ALL, "");

    // Parsed FIRST because it decides where our own chatter goes. In
    // external-launcher mode stdout belongs to the JSON event stream the
    // launcher parses line by line, so every human-facing line we print must
    // go to stderr instead — otherwise our banner is the first thing it tries
    // to parse as JSON. For the same reason we never pause on Enter there:
    // nobody is attached to stdin.
    const std::wstring connect_addr = parse_connect(argc, argv);
    const bool  headless = !connect_addr.empty();
    FILE* const say      = headless ? stderr : stdout;

    std::fwprintf(say, L"FalloutWorld / FoM-lite native launcher\n");

    // 1) Determine side. --side A/B preferred; fall back to interactive prompt
    //    for the "double-clicked the exe" UX. A malformed --side errors out
    //    immediately rather than falling through to the prompt.

    char side = parse_side(argc, argv);
    if (side == '!') {
        std::fwprintf(stderr,
            L"[FoM] ERROR: --side requires argument A or B\n");
        return 1;
    }
    if (side == 0) {
        // --connect implies non-interactive: the external launcher spawns us
        // and reads stdout, so a prompt would block forever on a stdin nobody
        // is attached to. Default to A instead.
        side = connect_addr.empty() ? prompt_side() : 'A';
        if (side != 'A' && side != 'B') side = 0;
    }
    if (side != 'A' && side != 'B') {
        std::fwprintf(stderr,
            L"[FoM] ERROR: side must be A or B (use --side A|B)\n");
        return 1;
    }

    // 2) Resolve python.exe and our own dir. The Python launcher is run with
    //    CWD = our dir (== repo root after deploy).
    const std::wstring py = find_python();
    if (py.empty()) {
        std::fwprintf(stderr,
            L"[FoM] ERROR: python.exe not found in PATH.\n"
            L"       Install Python 3.12+ (https://python.org) or fix PATH.\n");
        if (!headless) {   // no one is there to press Enter
            std::wprintf(L"Press Enter to close...");
            std::fflush(stdout);
            (void)std::getchar();
        }
        return 1;
    }
    const std::wstring cwd = get_exe_dir();

    std::fwprintf(say, L"[FoM] python  : %ls\n", py.c_str());
    std::fwprintf(say, L"[FoM] repo    : %ls\n", cwd.c_str());
    std::fwprintf(say, L"[FoM] side    : %c\n", side);
    std::fwprintf(say, L"[FoM] starting Python launcher...\n\n");
    std::fflush(say);

    // 3) Build a cmdline like:  "C:\...\python.exe" -u -m launcher.main --side A
    //    CreateProcessW needs a writable buffer for lpCommandLine.
    std::wstring cmd;
    cmd.reserve(256);
    cmd  = shell_quote(py);
    cmd += L" -u -m launcher.main --side ";
    cmd += (side == 'A' ? L"A" : L"B");
    if (!connect_addr.empty()) {
        // Forwarded verbatim. We deliberately do NOT redirect the child's
        // streams, so its JSON event lines land on OUR stdout and the external
        // launcher reads them straight through.
        cmd += L" --connect ";
        cmd += shell_quote(connect_addr);
    }
    // v19 PIENUVO — login proof + display name, minted by the external
    // launcher, forwarded verbatim down to the python launcher which writes
    // them into fw_config.ini for the DLL.
    const std::wstring auth_blob = parse_value_flag(argc, argv, L"--auth");
    const std::wstring nickname  = parse_value_flag(argc, argv, L"--name");
    const std::wstring client_id = parse_value_flag(argc, argv, L"--client-id");
    if (!auth_blob.empty()) {
        cmd += L" --auth ";
        cmd += shell_quote(auth_blob);
    }
    if (!nickname.empty()) {
        cmd += L" --name ";
        cmd += shell_quote(nickname);
    }
    if (!client_id.empty()) {
        cmd += L" --client-id ";
        cmd += shell_quote(client_id);
    }
    // Build 69 control run — see start_client_B_TEST.bat.
    if (has_flag(argc, argv, L"--no-mirror-suppress")) {
        cmd += L" --no-mirror-suppress";
    }
    std::wstring mutable_cmd = cmd;   // CreateProcess requires writable

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    const BOOL ok = CreateProcessW(
        /*lpApplicationName*/ nullptr,
        /*lpCommandLine*/     mutable_cmd.data(),
        /*lpProcessAttributes*/ nullptr,
        /*lpThreadAttributes*/  nullptr,
        /*bInheritHandles*/   TRUE,
        /*dwCreationFlags*/   0,
        /*lpEnvironment*/     nullptr,
        /*lpCurrentDirectory*/ cwd.c_str(),
        &si, &pi);

    if (!ok) {
        const DWORD err = GetLastError();
        std::fwprintf(stderr, L"[FoM] ERROR: CreateProcess failed (err=%lu)\n",
                      static_cast<unsigned long>(err));
        if (!headless) {   // no one is there to press Enter
            std::wprintf(L"Press Enter to close...");
            std::fflush(stdout);
            (void)std::getchar();
        }
        return 2;
    }

    // 4) Minimize our own console so it stops sitting on top of the game.
    //    The B3.b main-menu auto-Continue hook in the DLL uses PostMessage
    //    (foreground-independent), but some users rely on keyboard focus
    //    landing on the game window by default — this reduces confusion.
    if (const HWND con = GetConsoleWindow()) {
        ShowWindow(con, SW_MINIMIZE);
    }

    // 5) Wait on child, return its exit code.
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD rc = 0;
    if (!GetExitCodeProcess(pi.hProcess, &rc)) rc = 2;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    std::fwprintf(say, L"\n[FoM] Python launcher exited rc=%lu\n",
                 static_cast<unsigned long>(rc));
    if (!headless) {
        std::wprintf(L"Press Enter to close...");
        std::fflush(stdout);
        (void)std::getchar();
    }
    return static_cast<int>(rc);
}
