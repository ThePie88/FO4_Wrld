// chat_overlay — implementation. The why is in chat_overlay.h.

#include "chat_overlay.h"

#include <windows.h>

#include <atomic>
#include <cfloat>
#include <deque>
#include <mutex>
#include <vector>

#include "imgui.h"
#include "imgui_impl_win32.h"

#include "overlay.h"
#include "../log.h"
#include "../net/client.h"
#include "../net/peer_names.h"
#include "../native/appearance_recipe.h"
#include "../native/scene_inject.h"

// Global scope on purpose — see the same declaration in editor_overlay.cpp.
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(
    HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace fw::render::chat {

namespace {

constexpr std::size_t kKeep = 50;   // lines kept in memory
constexpr std::size_t kShow = 8;    // lines on screen
// 200 bytes of UTF-8 plus the terminator. The server cuts at 200 CHARACTERS
// (CHAT_MAX_CHARS), so a line typed here never reaches that cut.
constexpr std::size_t kInputBytes = 200 + 1;

// The editor's Pip-Boy green for names, near-white for what they say.
constexpr ImVec4 kName  {46.0f / 255.0f, 255.0f / 255.0f, 123.0f / 255.0f, 1.00f};
constexpr ImVec4 kText  {0.94f, 0.96f, 0.95f, 1.00f};
constexpr ImVec4 kNotice{0.62f, 0.70f, 0.66f, 1.00f};

struct Line {
    std::string name;   // empty for a notice of our own ("not sent")
    std::string text;
};

std::mutex        g_mtx;
std::deque<Line>  g_lines;
std::atomic<bool> g_has_lines{false};
std::atomic<bool> g_typing{false};

// Main thread only.
bool g_focus_pending  = false;   // first frame of an open box: cursor goes in
bool g_eat_open_enter = false;   // the rest of the keystroke that opened it
char g_input[kInputBytes] = {};

void push_line(Line l) {
    std::lock_guard lk(g_mtx);
    g_lines.push_back(std::move(l));
    while (g_lines.size() > kKeep) g_lines.pop_front();
    g_has_lines.store(true, std::memory_order_release);
}

std::uintptr_t game_base() {
    static const std::uintptr_t b = reinterpret_cast<std::uintptr_t>(
        GetModuleHandleW(L"Fallout4.exe"));
    return b;
}

// Why the chat must stay out of the way right now, or nullptr when it may
// open and draw. The same three conditions hide the history.
const char* refusal(std::uintptr_t base) {
    if (fw::native::appearance::editing())       return "character creation is open";
    if (!fw::native::ghost_scene_settled())       return "not settled in the world";
    if (fw::render::overlay::in_menu_mode(base)) return "the game is in menu mode";
    return nullptr;
}

// ImGui keeps its own idea of which keys are down. The keystroke that sends a
// line can finish after the box has closed, and a key ImGui still believes is
// held never produces a new "pressed" — the next Enter would not send.
void reset_imgui_keys() {
    if (ImGui::GetCurrentContext()) ImGui::GetIO().ClearInputKeys();
}

void open_box() {
    g_input[0]       = '\0';
    g_focus_pending  = true;
    g_eat_open_enter = true;
    reset_imgui_keys();
    g_typing.store(true, std::memory_order_release);
    FW_LOG("[chat] input open — the game's controls are paused until Enter "
           "or Escape");
}

void close_box(const char* why) {
    g_typing.store(false, std::memory_order_release);
    g_focus_pending  = false;
    g_eat_open_enter = false;
    g_input[0]       = '\0';
    reset_imgui_keys();
    FW_LOG("[chat] input closed (%s) — controls back to the game", why);
}

std::string trimmed(const char* s) {
    const std::string t(s);
    const auto a = t.find_first_not_of(' ');
    if (a == std::string::npos) return {};
    return t.substr(a, t.find_last_not_of(' ') - a + 1);
}

// While the box is open, the only raw input the game may still see is a
// release (see the header). Anything else, including a message that cannot be
// read, is swallowed.
bool raw_input_is_release(LPARAM lp) {
    RAWINPUT ri{};
    UINT size = sizeof(ri);
    if (GetRawInputData(reinterpret_cast<HRAWINPUT>(lp), RID_INPUT, &ri, &size,
                        sizeof(RAWINPUTHEADER)) == static_cast<UINT>(-1)) {
        return false;
    }
    if (ri.header.dwType == RIM_TYPEKEYBOARD) {
        return (ri.data.keyboard.Flags & RI_KEY_BREAK) != 0;
    }
    if (ri.header.dwType == RIM_TYPEMOUSE) {
        constexpr USHORT kUps = RI_MOUSE_LEFT_BUTTON_UP | RI_MOUSE_RIGHT_BUTTON_UP |
                                RI_MOUSE_MIDDLE_BUTTON_UP | RI_MOUSE_BUTTON_4_UP |
                                RI_MOUSE_BUTTON_5_UP;
        return (ri.data.mouse.usButtonFlags & kUps) != 0;
    }
    return false;
}

void send_input() {
    const std::string line = trimmed(g_input);
    if (line.empty()) { close_box("empty line, nothing sent"); return; }
    if (fw::net::client().send_chat(line)) {
        FW_DBG("[chat] sent %zu byte(s)", line.size());
        close_box("sent");
        return;
    }
    // Said on screen, not only in the log: a line that silently vanished
    // would read as "nobody answered".
    FW_WRN("[chat] not sent: no session with the server right now");
    push_line(Line{std::string(), "(not sent: no connection to the server)"});
    close_box("not sent");
}

}  // namespace

void on_line(const std::string& sender_id, const std::string& text) {
    std::string name = fw::net::peer_names::display(sender_id);
    FW_LOG("[chat] <%s> %s", name.c_str(), text.c_str());
    push_line(Line{std::move(name), text});
}

void notice(const std::string& text) {
    FW_LOG("[chat] notice: %s", text.c_str());
    push_line(Line{std::string(), text});
}

bool typing() noexcept { return g_typing.load(std::memory_order_acquire); }

bool wants_frame(std::uintptr_t module_base) {
    if (typing()) return true;   // draw() closes the box if the world went away
    if (!g_has_lines.load(std::memory_order_acquire)) return false;
    return refusal(module_base) == nullptr;
}

void draw(std::uintptr_t module_base) {
    bool is_typing = typing();
    // The game can open a menu or start a load by itself — a scripted message
    // box, a death — and that must not leave the controls paused behind it.
    if (is_typing) {
        if (const char* why = refusal(module_base)) {
            close_box(why);
            is_typing = false;
        }
    }

    std::vector<Line> shown;
    {
        std::lock_guard lk(g_mtx);
        const std::size_t n = g_lines.size();
        const std::size_t from = n > kShow ? n - kShow : 0;
        shown.assign(g_lines.begin() + static_cast<std::ptrdiff_t>(from),
                     g_lines.end());
    }
    if (shown.empty() && !is_typing) return;

    // Sized from the screen, so it reads the same at 1080p and 1440p: 18 px
    // at 1080. Left edge, above the middle, clear of the compass and the
    // health bar at the bottom left and of the quest notices at the top.
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    const float W = vp->Size.x;
    const float H = vp->Size.y;
    float px = H / 60.0f;
    if (px < 14.0f) px = 14.0f;
    if (px > 30.0f) px = 30.0f;
    const float x      = vp->Pos.x + W * 0.012f;
    const float bottom = vp->Pos.y + H * 0.62f;
    const float width  = W * 0.30f;

    ImGui::PushFont(fw::render::overlay::chat_font(), px);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8.0f, 6.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, 2.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);

    if (!shown.empty()) {
        constexpr ImGuiWindowFlags kHistory =
            ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoInputs |
            ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoFocusOnAppearing |
            ImGuiWindowFlags_NoBringToFrontOnFocus |
            ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_AlwaysAutoResize;
        // Anchored by its BOTTOM-left corner, so new lines push the box up
        // instead of down over the input.
        ImGui::SetNextWindowPos(ImVec2(x, bottom), ImGuiCond_Always,
                                ImVec2(0.0f, 1.0f));
        ImGui::SetNextWindowSize(ImVec2(width, 0.0f));   // height auto-fits
        ImGui::SetNextWindowBgAlpha(is_typing ? 0.35f : 0.20f);
        if (ImGui::Begin("##fw_chat_history", nullptr, kHistory)) {
            ImGui::PushTextWrapPos(0.0f);
            for (const Line& l : shown) {
                if (l.name.empty()) {
                    ImGui::PushStyleColor(ImGuiCol_Text, kNotice);
                    ImGui::TextUnformatted(l.text.c_str());
                    ImGui::PopStyleColor();
                    continue;
                }
                ImGui::PushStyleColor(ImGuiCol_Text, kName);
                ImGui::TextUnformatted(l.name.c_str());
                ImGui::PopStyleColor();
                ImGui::SameLine(0.0f, 0.0f);
                ImGui::PushStyleColor(ImGuiCol_Text, kText);
                ImGui::TextUnformatted(": ");
                ImGui::SameLine(0.0f, 0.0f);
                ImGui::TextUnformatted(l.text.c_str());
                ImGui::PopStyleColor();
            }
            ImGui::PopTextWrapPos();
        }
        ImGui::End();
    }

    if (is_typing) {
        constexpr ImGuiWindowFlags kInput =
            ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoSavedSettings |
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_AlwaysAutoResize;
        ImGui::SetNextWindowPos(ImVec2(x, bottom + 4.0f), ImGuiCond_Always);
        ImGui::SetNextWindowSize(ImVec2(width, 0.0f));
        ImGui::SetNextWindowBgAlpha(0.55f);
        if (g_focus_pending) ImGui::SetNextWindowFocus();
        bool send = false;
        bool cancel = false;
        if (ImGui::Begin("##fw_chat_input", nullptr, kInput)) {
            ImGui::SetNextItemWidth(-FLT_MIN);
            // Asked again every frame until ImGui reports the box active: a
            // window's first frame is a layout pass, and a request made only
            // then can land on nothing.
            if (g_focus_pending) ImGui::SetKeyboardFocusHere();
            send = ImGui::InputText("##fw_chat_text", g_input, sizeof(g_input),
                                    ImGuiInputTextFlags_EnterReturnsTrue);
            if (g_focus_pending && ImGui::IsItemActive()) g_focus_pending = false;
            cancel = ImGui::IsKeyPressed(ImGuiKey_Escape, false);
        }
        ImGui::End();
        if (send)        send_input();
        else if (cancel) close_box("Escape, nothing sent");
    }

    ImGui::PopStyleVar(3);
    ImGui::PopFont();
}

bool wndproc(void* hwnd, unsigned int msg, unsigned long long wparam,
             long long lparam) {
    const HWND   h  = static_cast<HWND>(hwnd);
    const WPARAM wp = static_cast<WPARAM>(wparam);
    const LPARAM lp = static_cast<LPARAM>(lparam);

    if (!typing()) {
        // The one message the chat wants while closed: a fresh Enter.
        if (msg != WM_KEYDOWN || wp != VK_RETURN) return false;
        if ((lp & 0x40000000) != 0) return false;   // auto-repeat of a held Enter
        if (const char* why = refusal(game_base())) {
            FW_LOG("[chat] Enter left to the game: %s", why);
            return false;
        }
        open_box();
        return true;   // the opening Enter is ours
    }

    switch (msg) {
        case WM_INPUT:
            if (raw_input_is_release(lp)) return false;
            // DefWindowProc still has to see WM_INPUT so the system can free
            // the raw input buffer (MSDN; the editor does the same).
            DefWindowProcW(h, msg, wp, lp);
            return true;

        case WM_KEYDOWN:
        case WM_KEYUP:
        case WM_CHAR:
            // The keystroke that opened the box still has its WM_CHAR '\r'
            // and its key-up to come. Handed to ImGui they would press Enter
            // in an empty box and close it on the spot.
            if (g_eat_open_enter) {
                if ((msg == WM_KEYDOWN && wp == VK_RETURN) ||
                    (msg == WM_CHAR && wp == '\r')) {
                    return true;
                }
                if (msg == WM_KEYUP && wp == VK_RETURN) {
                    g_eat_open_enter = false;
                    return true;
                }
            }
            ::ImGui_ImplWin32_WndProcHandler(h, msg, wp, lp);
            return true;

        // The mouse is not the box's, and not the game's either while it is
        // open: the camera stays where it was.
        case WM_MOUSEMOVE:
        case WM_LBUTTONDOWN: case WM_LBUTTONUP: case WM_LBUTTONDBLCLK:
        case WM_RBUTTONDOWN: case WM_RBUTTONUP: case WM_RBUTTONDBLCLK:
        case WM_MBUTTONDOWN: case WM_MBUTTONUP: case WM_MBUTTONDBLCLK:
        case WM_XBUTTONDOWN: case WM_XBUTTONUP: case WM_XBUTTONDBLCLK:
        case WM_MOUSEWHEEL:  case WM_MOUSEHWHEEL:
            return true;

        // Everything else passes: WM_SYSKEYDOWN and friends (ALT+F4,
        // ALT+TAB), focus, activation, the cursor, timers.
        default:
            return false;
    }
}

}  // namespace fw::render::chat
