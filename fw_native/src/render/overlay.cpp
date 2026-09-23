// overlay — implementation. The why is in overlay.h.

#include "overlay.h"

#include <windows.h>
#include <d3d11.h>

#include <atomic>
#include <string>

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"

#include "present_hook.h"
#include "editor_overlay.h"
#include "chat_overlay.h"
#include "nametags.h"
#include "../log.h"
#include "../native/appearance_recipe.h"

namespace fw::render::overlay {

namespace {

std::atomic<bool> g_ready{false};
std::atomic<bool> g_failed{false};   // one attempt; do not retry every frame
ImFont* g_chat_font = nullptr;
ImFont* g_tag_font  = nullptr;

// Main. The pointer to the singleton is the qword at RVA 0x32D2020
// (qword_1430DBF78[257045] in the decomp). The Papyrus native behind
// Utility.IsInMenuMode is sub_14118F210, and its whole body is
// `return *(u8*)(Main + 464)`. re/B6.5_npc_pipeline_AGENT_A.md had already met
// the same byte as the process lists' pause gate, without its name.
constexpr std::uintptr_t MAIN_PTR_RVA          = 0x032D2020;
constexpr std::size_t    MAIN_IN_MENU_MODE_OFF = 0x1D0;

// A font from the Windows font folder, or null when the file is not there.
// Checked before handing the path to ImGui, whose loader asserts on a missing
// file instead of returning quietly.
ImFont* load_windows_font(const char* file) {
    wchar_t dir[MAX_PATH] = {};
    const UINT n = GetWindowsDirectoryW(dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return nullptr;
    std::wstring wpath = std::wstring(dir) + L"\\Fonts\\";
    for (const char* p = file; *p; ++p) wpath.push_back(static_cast<wchar_t>(*p));
    if (GetFileAttributesW(wpath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        FW_WRN("[overlay] font %s not found in the Windows font folder — "
               "that text falls back to ImGui's default font", file);
        return nullptr;
    }
    // ImGui takes UTF-8 and converts back to wide itself on Windows.
    const int len = WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(), -1,
                                        nullptr, 0, nullptr, nullptr);
    if (len <= 1) return nullptr;
    std::string path(static_cast<std::size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(), -1, path.data(), len,
                        nullptr, nullptr);
    // The size is only a default: every caller pushes the font with an
    // explicit size, and ImGui 1.92 rasterises any size on demand.
    return ImGui::GetIO().Fonts->AddFontFromFileTTF(path.c_str(), 18.0f);
}

// Bring ImGui up against the GAME's device and context rather than any of our
// own. There is nothing to create: present_hook resolves both from fixed
// globals, and the swapchain they belong to was proven to be the one Present
// is called on. (This was the editor's try_init until 2026-09-23.)
bool try_init() {
    if (g_failed.load(std::memory_order_relaxed)) return false;

    const GameD3D g = game_d3d();
    if (!g.device || !g.context || !g.hwnd) {
        // Normal before the renderer has come up; say nothing and try next frame.
        return false;
    }

    IMGUI_CHECKVERSION();
    if (!ImGui::CreateContext()) {
        FW_ERR("[overlay] ImGui::CreateContext failed");
        g_failed.store(true, std::memory_order_relaxed);
        return false;
    }
    ImGuiIO& io = ImGui::GetIO();
    // No ini and no log file. This is a game overlay: writing imgui.ini into the
    // game directory would be litter, and it would also persist window positions
    // that we set ourselves every frame anyway.
    io.IniFilename = nullptr;
    io.LogFilename = nullptr;
    // The OS cursor is the game's business. ImGui now runs a frame during
    // normal play too, when the game keeps the cursor hidden, and its Win32
    // backend otherwise calls SetCursor whenever the shape it wants changes.
    // The editor, which does want a cursor, answers WM_SETCURSOR itself.
    io.ConfigFlags |= ImGuiConfigFlags_NoMouseCursorChange;
    editor::apply_style();

    // The default font FIRST, so it stays the default: the editor panel was
    // designed with it and does not push a font of its own.
    io.Fonts->AddFontDefault();
    g_chat_font = load_windows_font("segoeui.ttf");
    g_tag_font  = load_windows_font("segoeuib.ttf");

    if (!ImGui_ImplWin32_Init(g.hwnd)) {
        FW_ERR("[overlay] ImGui_ImplWin32_Init failed (hwnd=%p)", g.hwnd);
        ImGui::DestroyContext();
        g_failed.store(true, std::memory_order_relaxed);
        return false;
    }
    if (!ImGui_ImplDX11_Init(static_cast<ID3D11Device*>(g.device),
                             static_cast<ID3D11DeviceContext*>(g.context))) {
        FW_ERR("[overlay] ImGui_ImplDX11_Init failed (device=%p context=%p)",
               g.device, g.context);
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        g_failed.store(true, std::memory_order_relaxed);
        return false;
    }

    g_ready.store(true, std::memory_order_release);
    FW_LOG("[overlay] ImGui %s up on the game's own device=%p context=%p "
           "hwnd=%p — drawing into the game's live backbuffer RTV, owning no "
           "render target of its own; fonts chat=%p tag=%p", IMGUI_VERSION,
           g.device, g.context, g.hwnd, static_cast<void*>(g_chat_font),
           static_cast<void*>(g_tag_font));
    return true;
}

}  // namespace

bool ready() noexcept { return g_ready.load(std::memory_order_acquire); }
ImFont* chat_font() noexcept { return g_chat_font; }
ImFont* tag_font() noexcept { return g_tag_font; }

bool in_menu_mode(std::uintptr_t module_base) noexcept {
    if (!module_base) return false;
    __try {
        const auto* main = *reinterpret_cast<const std::uint8_t* const*>(
            module_base + MAIN_PTR_RVA);
        if (!main) return false;
        return main[MAIN_IN_MENU_MODE_OFF] != 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void on_frame(std::uintptr_t module_base) {
    // THE EDITOR'S INPUT CAPTURE FOLLOWS ITS FLAG, and it has to be reconciled
    // here -- before the early-out -- because releasing it is as important as
    // taking it. (Moved from editor::on_frame with the frame itself.)
    //
    // It used to be taken and released by the F2 key handler and nowhere else,
    // which meant the capture only ever happened because somebody pressed a key.
    // When the SERVER asked for the ritual the panel appeared with the game still
    // reading the mouse: the character turned with it and raised a weapon on a
    // left click, and the cursor stayed hidden. Pressing F2 twice fixed it, which
    // made it look like a timing problem and was actually a missing caller.
    //
    // This is the second time the same mistake has been made in this feature --
    // the staging had it too, for the same reason -- so the rule is worth stating:
    // anything that must be true WHILE THE EDITOR IS OPEN belongs to the flag, not
    // to whatever happened to open it.
    const bool editing = fw::native::appearance::editing();
    if (editor::input_captured() != editing) {
        editor::set_input_captured(module_base, editing);
    }

    // Nothing to draw is the common case before anyone else joins, and it must
    // cost nothing: checked before ImGui is even brought up.
    const bool chat = chat::wants_frame(module_base);
    const bool tags = nametags::wants_frame(module_base);
    if (!editing && !chat && !tags) return;

    if (!g_ready.load(std::memory_order_acquire)) {
        if (!try_init()) return;
    }

    if (editing) editor::prepare_frame(module_base);

    const GameD3D g = game_d3d();
    if (!g.context || !g.backbuf_rtv) return;

    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();
    if (tags)    nametags::draw(module_base);
    if (chat)    chat::draw(module_base);
    if (editing) editor::draw(module_base);
    ImGui::Render();

    // Bind the GAME's render target, then let ImGui's backend draw. The backend
    // saves and restores the pipeline state around its own draw, so the only
    // state we perturb is this binding — and we are at Present, so the game's
    // frame is already composited.
    auto* ctx = static_cast<ID3D11DeviceContext*>(g.context);
    auto* rtv = static_cast<ID3D11RenderTargetView*>(g.backbuf_rtv);
    ctx->OMSetRenderTargets(1, &rtv, nullptr);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
}

void shutdown() {
    // Down for good: the only caller is the Present detour after a fault
    // inside the overlay, and bringing ImGui back up would only fault again
    // next frame.
    g_failed.store(true, std::memory_order_relaxed);
    if (!g_ready.exchange(false, std::memory_order_acq_rel)) return;
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    g_chat_font = nullptr;
    g_tag_font  = nullptr;
    FW_LOG("[overlay] ImGui shut down");
}

}  // namespace fw::render::overlay
