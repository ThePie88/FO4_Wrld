#include "editor_overlay.h"

#include <cstring>

#include <windows.h>
#include <d3d11.h>

#include <atomic>

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"

#include "present_hook.h"
#include "../log.h"
#include "../native/appearance_recipe.h"
#include "../native/chargen_catalog.h"

// imgui_impl_win32.h keeps this declaration inside an `#if 0` on purpose, so it
// does not drag <windows.h> into the helper, and tells you to copy the line into
// your own .cpp. GLOBAL scope: an earlier attempt put it inside the namespace
// below, which quietly created a different symbol and failed at link.
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(
    HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace fw::render::editor {

namespace cat    = fw::native::catalog;
namespace appear = fw::native::appearance;

namespace {

std::atomic<bool> g_ready{false};
std::atomic<bool> g_failed{false};   // one attempt; do not retry every frame

// The style tokens are the user's, recovered from the brief they gave the demo:
// dark background, Pip-Boy green #2eff7b as the accent, thin borders, and no
// rounding anywhere. Scanlines were considered and deliberately dropped.
constexpr ImVec4 kGreen   {46.0f / 255.0f, 255.0f / 255.0f, 123.0f / 255.0f, 1.00f};
constexpr ImVec4 kGreenDim{46.0f / 255.0f, 255.0f / 255.0f, 123.0f / 255.0f, 0.35f};
constexpr ImVec4 kPanelBg {0.035f, 0.055f, 0.045f, 0.92f};
constexpr ImVec4 kText    {0.82f, 0.90f, 0.85f, 1.00f};
constexpr ImVec4 kTextDim {0.50f, 0.58f, 0.54f, 1.00f};

void apply_style() {
    ImGuiStyle& s = ImGui::GetStyle();
    // Square everything. A RobCo terminal has no rounded corners, and this is
    // most of what makes ImGui stop looking like a debug tool.
    s.WindowRounding    = 0.0f;
    s.ChildRounding     = 0.0f;
    s.FrameRounding     = 0.0f;
    s.PopupRounding     = 0.0f;
    s.ScrollbarRounding = 0.0f;
    s.GrabRounding      = 0.0f;
    s.TabRounding       = 0.0f;
    s.WindowBorderSize  = 1.0f;
    s.FrameBorderSize   = 1.0f;
    s.WindowPadding     = ImVec2(14, 12);
    s.ItemSpacing       = ImVec2(8, 7);

    ImVec4* c = s.Colors;
    c[ImGuiCol_WindowBg]        = kPanelBg;
    c[ImGuiCol_ChildBg]         = ImVec4(0, 0, 0, 0.18f);
    c[ImGuiCol_Border]          = kGreenDim;
    c[ImGuiCol_Text]            = kText;
    c[ImGuiCol_TextDisabled]    = kTextDim;
    c[ImGuiCol_FrameBg]         = ImVec4(0.08f, 0.12f, 0.10f, 0.85f);
    c[ImGuiCol_FrameBgHovered]  = ImVec4(0.12f, 0.20f, 0.15f, 0.90f);
    c[ImGuiCol_FrameBgActive]   = ImVec4(0.14f, 0.26f, 0.18f, 0.95f);
    c[ImGuiCol_TitleBg]         = ImVec4(0.05f, 0.09f, 0.07f, 1.00f);
    c[ImGuiCol_TitleBgActive]   = ImVec4(0.06f, 0.13f, 0.09f, 1.00f);
    c[ImGuiCol_Tab]             = ImVec4(0.06f, 0.10f, 0.08f, 1.00f);
    c[ImGuiCol_TabHovered]      = ImVec4(0.12f, 0.24f, 0.16f, 1.00f);
    c[ImGuiCol_TabSelected]     = ImVec4(0.10f, 0.20f, 0.14f, 1.00f);
    c[ImGuiCol_Header]          = ImVec4(0.10f, 0.20f, 0.14f, 0.80f);
    c[ImGuiCol_HeaderHovered]   = ImVec4(0.14f, 0.28f, 0.19f, 0.90f);
    c[ImGuiCol_Separator]       = kGreenDim;
    c[ImGuiCol_SliderGrab]      = kGreen;
    c[ImGuiCol_SliderGrabActive]= kGreen;
    c[ImGuiCol_CheckMark]       = kGreen;
    c[ImGuiCol_ScrollbarBg]     = ImVec4(0, 0, 0, 0.25f);
    c[ImGuiCol_ScrollbarGrab]   = kGreenDim;
}

// Bring ImGui up against the GAME's device and context rather than any of our
// own. There is nothing to create: §28 resolves both from fixed globals and the
// swapchain they belong to was proven to be the one Present is called on.
bool try_init(std::uintptr_t module_base) {
    if (g_failed.load(std::memory_order_relaxed)) return false;

    const GameD3D g = game_d3d();
    if (!g.device || !g.context || !g.hwnd) {
        // Normal before the renderer has come up; say nothing and try next frame.
        return false;
    }

    IMGUI_CHECKVERSION();
    if (!ImGui::CreateContext()) {
        FW_ERR("[editor] ImGui::CreateContext failed");
        g_failed.store(true, std::memory_order_relaxed);
        return false;
    }
    ImGuiIO& io = ImGui::GetIO();
    // No ini and no log file. This is a game overlay: writing imgui.ini into the
    // game directory would be litter, and it would also persist window positions
    // that we set ourselves every frame anyway.
    io.IniFilename = nullptr;
    io.LogFilename = nullptr;
    apply_style();

    if (!ImGui_ImplWin32_Init(g.hwnd)) {
        FW_ERR("[editor] ImGui_ImplWin32_Init failed (hwnd=%p)", g.hwnd);
        ImGui::DestroyContext();
        g_failed.store(true, std::memory_order_relaxed);
        return false;
    }
    if (!ImGui_ImplDX11_Init(static_cast<ID3D11Device*>(g.device),
                             static_cast<ID3D11DeviceContext*>(g.context))) {
        FW_ERR("[editor] ImGui_ImplDX11_Init failed (device=%p context=%p)",
               g.device, g.context);
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        g_failed.store(true, std::memory_order_relaxed);
        return false;
    }

    g_ready.store(true, std::memory_order_release);
    FW_LOG("[editor] ImGui %s up on the game's own device=%p context=%p hwnd=%p "
           "— drawing into the game's live backbuffer RTV, owning no render "
           "target of its own", IMGUI_VERSION, g.device, g.context, g.hwnd);
    return true;
}


// One scrollable list of named options. The row that matches what the player is
// WEARING is highlighted, read live from the character rather than from any state
// of our own — so the panel can never disagree with what is on screen.
//
// Returns the form id that was clicked, or 0.
std::uint32_t option_list(const char* id,
                          const std::vector<fw::native::catalog::Option>& opts,
                          std::uint32_t current, float height) {
    std::uint32_t clicked = 0;
    if (ImGui::BeginChild(id, ImVec2(0, height), ImGuiChildFlags_Borders)) {
        if (opts.empty()) ImGui::TextDisabled("(empty)");
        for (const auto& o : opts) {
            const bool sel = (o.form_id == current);
            // Identified by form id, never by the display name. Two forms can
            // legitimately share a name — vanilla has three "Dark Brown" colour
            // forms — and ImGui derives a widget's identity from its label, so
            // name-labelled rows collided: it drew them outlined in red and
            // clicking one could act on the other. The form id is unique by
            // construction, which is exactly what an ID needs to be.
            ImGui::PushID(static_cast<int>(o.form_id));
            if (ImGui::Selectable(o.name.c_str(), sel)) clicked = o.form_id;
            ImGui::PopID();
        }
    }
    ImGui::EndChild();
    return clicked;
}


// One tint group rendered as a list. Masks are on/off rows; palette templates
// expand into their own colour rows.
//
// WHERE EACH GROUP IS SHOWN is a provisional decision, taken from the group's own
// name in the game data rather than invented: Brows sits with the face, the skin
// tones and blemishes sit under Skin, and the paint, tattoos, damage and grime
// sit under Marks. The tab structure itself is not ours to change.
// Which tint groups hold ONE choice at a time.
//
// This is not in the data. The engine's exclusivity lives in the menu, not in the
// record: sub_140BBFDC0 keeps the group's previously picked index at menu+904 and,
// when its `a5` argument is set, clears that entry with
// sub_14065DAB0(npc, prevTintId, 0.0, -1) before applying the new one. So which
// groups are single-select is a UI decision the menu makes, and nothing readable
// says which.
//
// Brows is obviously one of them -- a face has one pair of eyebrows, and without
// this all seventeen could be worn at once, which is what the first version let
// happen. The rest are left additive because layering a scar with a tattoo and
// some dirt is a real thing to want. If any of the others should be single-select
// too, they belong in this list and nowhere else.
bool group_is_exclusive(const char* name) noexcept {
    return name && std::strcmp(name, "Brows") == 0;
}

void tint_group_ui(std::uintptr_t base, const char* group_name, float height) {
    const auto* g = cat::tint_group(group_name);
    if (!g) { ImGui::TextDisabled("(no %s data for this race)", group_name);
              return; }
    if (ImGui::BeginChild(group_name, ImVec2(0, height),
                          ImGuiChildFlags_Borders)) {
        if (g->items.empty()) ImGui::TextDisabled("(empty)");
        for (const auto& it : g->items) {
            ImGui::PushID(static_cast<int>(it.tint_id));
            std::uint8_t  cur_i = 0;
            std::uint32_t cur_c = 0;
            const bool on = appear::current_tint(base, it.tint_id,
                                                 &cur_i, &cur_c);
            if (!it.palette) {
                // A mask is a shape with an intensity. Clicking toggles it: full
                // on, or zero -- and zero is how the engine deletes the entry.
                char label[192];
                std::snprintf(label, sizeof(label), "%s%s", it.name.c_str(),
                              on ? "  *" : "");
                if (ImGui::Selectable(label, on)) {
                    // In a single-select group, drop whatever else is worn first
                    // and defer the rebuild so the whole change costs one.
                    if (!on && group_is_exclusive(group_name)) {
                        for (const auto& other : g->items) {
                            if (other.tint_id == it.tint_id) continue;
                            if (!appear::current_tint(base, other.tint_id,
                                                      nullptr, nullptr)) {
                                continue;
                            }
                            appear::set_tint(base, other.tint_id, 0,
                                             0xFFFFFFFFu, /*rebuild=*/false);
                        }
                    }
                    // 0xFFFFFFFF, not 0: a mask has no colour, and zero would be
                    // black. Intensity 0 is how the engine deletes the entry.
                    appear::set_tint(base, it.tint_id, on ? 0 : 100, 0xFFFFFFFFu);
                }
            } else {
                if (ImGui::TreeNodeEx(it.name.c_str(),
                                      g->items.size() == 1
                                          ? ImGuiTreeNodeFlags_DefaultOpen : 0)) {
                    int ci = 0;
                    for (const auto& c : it.colours) {
                        // Keyed by position, not by form id. A palette may list
                        // the SAME colour form twice -- the Dirt group does, with
                        // two entries both named "black" -- and a form-id key made
                        // those two rows one widget, which is exactly the conflict
                        // ImGui reported on screen.
                        ImGui::PushID(ci++);
                        // With nothing applied, the row that is "selected" is
                        // the None entry -- otherwise removing a tint leaves the
                        // list showing no selection at all, which reads as a
                        // failed click.
                        const bool sel = on ? (c.alpha > 0.0f && c.rgb == cur_c)
                                            : (c.alpha <= 0.0f);
                        // 0x00BBGGRR: byte 0 is RED, settled from data.
                        const ImVec4 sw(
                            static_cast<float>((c.rgb) & 0xFF) / 255.0f,
                            static_cast<float>((c.rgb >> 8) & 0xFF) / 255.0f,
                            static_cast<float>((c.rgb >> 16) & 0xFF) / 255.0f,
                            1.0f);
                        ImGui::ColorButton("##sw", sw,
                                           ImGuiColorEditFlags_NoTooltip |
                                           ImGuiColorEditFlags_NoDragDrop,
                                           ImVec2(14, 14));
                        ImGui::SameLine();
                        if (ImGui::Selectable(c.name.c_str(), sel)) {
                            // THE ELEMENT'S ALPHA IS THE INTENSITY, zero
                            // included, and zero is how a tint is removed.
                            //
                            // The dump settles this: every palette begins with an
                            // entry named "None" at index 0 -- always the same
                            // form 0x001ABFD5, rgb 0, alpha 0.000, 83 of them
                            // across the groups -- and the real colours start at
                            // index 1 with alpha 1.000 (Dark Brown carries 0.900).
                            // So index 0 IS the off switch, and an intensity of 0
                            // makes the engine delete the entry as "same as the
                            // race default".
                            //
                            // Two earlier versions of this line got it wrong in
                            // opposite directions. The first computed 0% for every
                            // alpha-0 entry AND for the real ones, clearing
                            // everything. The second added a `? 100` fallback to
                            // stop that -- which turned the None entry into "paint
                            // it black at full strength", so None could not remove
                            // anything. The fallback was invented to guard a case
                            // the data says is meaningful. No fallback: use what
                            // the record says.
                            const int pct =
                                static_cast<int>(c.alpha * 100.0f + 0.5f);
                            appear::set_tint(base, it.tint_id,
                                             static_cast<std::uint8_t>(pct),
                                             pct == 0 ? 0xFFFFFFFFu : c.rgb);
                        }
                        ImGui::PopID();
                    }
                    ImGui::TreePop();
                }
            }
            ImGui::PopID();
        }
    }
    ImGui::EndChild();
}

// The panel. Right-hand third, full height, fixed — the user cannot drag or
// resize it, because its position is a consequence of where the camera sits in
// third person rather than a preference.
void draw_panel(std::uintptr_t base) {
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    const float w = vp->Size.x * 0.32f;
    ImGui::SetNextWindowPos(ImVec2(vp->Pos.x + vp->Size.x - w, vp->Pos.y));
    ImGui::SetNextWindowSize(ImVec2(w, vp->Size.y));

    const ImGuiWindowFlags flags =
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoTitleBar;

    if (!ImGui::Begin("##fw_editor", nullptr, flags)) {
        ImGui::End();
        return;
    }

    ImGui::PushStyleColor(ImGuiCol_Text, kGreen);
    ImGui::TextUnformatted("FO4 WORLD");
    ImGui::PopStyleColor();
    ImGui::TextDisabled("CHARACTER CREATION");
    ImGui::Separator();
    ImGui::Spacing();

    // Reserve the footer FIRST and put the tabs in a bounded child. An earlier
    // version placed the footer with SetCursorPosY after the tabs had already
    // taken every pixel, so the last list grew straight over the CONFIRM button
    // and buried it. Space is allocated before it is spent now.
    const float footer_h = ImGui::GetFrameHeightWithSpacing() + 10.0f;
    ImGui::BeginChild("##fw_body",
                      ImVec2(0, ImGui::GetContentRegionAvail().y - footer_h));
    if (ImGui::BeginTabBar("##fw_cats", ImGuiTabBarFlags_None)) {
        // The four categories the user settled on. Morphs and body are out by
        // decision: morph keys are undecoded and the body is always under
        // clothes. Everything below is a discrete named pick, not a slider —
        // which is why these will be lists and grids, with one intensity slider
        // wherever the category is a tint.
        if (ImGui::BeginTabItem("Face")) {
            const float h = ImGui::GetContentRegionAvail().y * 0.5f - 26.0f;
            ImGui::TextDisabled("EYES");
            if (auto id = option_list("##eyes", cat::parts_of_type(2),
                                      appear::current_part_of_type(base, 2), h)) {
                appear::swap_part(base, 2, id);
            }
            ImGui::TextDisabled("BROWS");
            tint_group_ui(base, "Brows", h * 0.6f);
            ImGui::TextDisabled("TEETH");
            if (auto id = option_list("##teeth", cat::parts_of_type(8),
                                      appear::current_part_of_type(base, 8),
                                      h * 0.4f)) {
                appear::swap_part(base, 8, id);
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Hair")) {
            const float h = ImGui::GetContentRegionAvail().y / 3.0f - 26.0f;
            ImGui::TextDisabled("STYLE");
            if (auto id = option_list("##hair", cat::parts_of_type(3),
                                      appear::current_part_of_type(base, 3), h)) {
                appear::swap_part(base, 3, id);
            }
            ImGui::TextDisabled("COLOUR");
            if (auto id = option_list("##hcol", cat::colours(),
                                      appear::current_hair_colour(base), h)) {
                appear::set_hair_colour(base, id);
            }
            ImGui::TextDisabled("FACIAL HAIR");
            if (auto id = option_list("##beard", cat::parts_of_type(4),
                                      appear::current_part_of_type(base, 4), h)) {
                appear::swap_part(base, 4, id);
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Skin")) {
            const float h = ImGui::GetContentRegionAvail().y * 0.5f - 26.0f;
            ImGui::TextDisabled("TONE");
            tint_group_ui(base, "SkinTints", h);
            ImGui::TextDisabled("BLEMISHES");
            tint_group_ui(base, "Blemishes", h);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Marks")) {
            const float h = ImGui::GetContentRegionAvail().y / 4.0f - 22.0f;
            ImGui::TextDisabled("WAR PAINT");
            tint_group_ui(base, "Face Paint", h);
            ImGui::TextDisabled("TATTOOS");
            tint_group_ui(base, "Face Tattoos", h);
            ImGui::TextDisabled("SCARS AND DAMAGE");
            tint_group_ui(base, "Damage", h);
            ImGui::TextDisabled("DIRT");
            tint_group_ui(base, "Grime", h);
            ImGui::EndTabItem();
        }
        // Present and labelled, not implemented. CharGenData+0x40 is a preset
        // list that has never been opened.
        if (ImGui::BeginTabItem("Preset")) {
            ImGui::PushStyleColor(ImGuiCol_Text, kGreen);
            ImGui::TextUnformatted("WIP");
            ImGui::PopStyleColor();
            ImGui::TextWrapped("Presets exist in the race data but have never "
                               "been opened.");
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    ImGui::EndChild();

    // Bottom strip. Its space was reserved above, so it cannot be pushed off.
    //
    // CONFIRM lowers the editing flag and nothing else, which is the whole trick:
    // everything that has to happen on confirmation is already keyed to that flag
    // going down. chargen_stage::sync teleports the player back to the origin and
    // restores the camera; appearance::set_editing publishes the finished recipe
    // on the next tick instead of waiting out its throttle; and the server starts
    // relaying this player to the other clients as soon as that recipe lands,
    // because a peer with no recipe is a peer still at the mirror.
    ImGui::Separator();
    if (ImGui::Button("CONFIRM", ImVec2(-1.0f, 0.0f))) {
        FW_LOG("[editor] CONFIRM - the character is committed: the player returns "
               "to the origin, the recipe is published, and peers may see them");
        // Order matters. Clearing `pending` first means the publisher is already
        // allowed to speak by the time the editing flag falls, so the finished
        // recipe goes out on the very next tick. Doing it the other way round
        // would drop that first publish on the floor.
        appear::set_chargen_pending(false);
        appear::set_editing(false);
        // No explicit release: on_frame reconciles the capture with the flag, and
        // one driver is the whole point.
    }

    ImGui::End();
}

}  // namespace

bool ready() noexcept { return g_ready.load(std::memory_order_acquire); }

// ---------------------------------------------------------------------- input

namespace {

// The engine's own "input dispatch is illegal right now" byte. Its two modal
// pumps do exactly `{ byte = 0; drain PeekMessage; byte = 1; }`, and its window
// procedure checks it before handling WM_INPUT, WM_MOUSEMOVE and WM_CHAR.
// Verified: seven references in .text, three reads at those three messages and
// four writes, all from those pumps.
constexpr std::uintptr_t INPUT_DISPATCH_OK_RVA = 0x02F26E4C;

// MenuCursor. The frame pump at RVA 0xC33190 reads the request refcount at +0x50
// and skips ClipCursor/SetCursorPos while it is non-zero — which is how a menu
// releases the mouse.
// bDisableAutoVanityMode:Camera. NO LONGER WRITTEN, and the reason is worth
// keeping because it inverts the original one.
//
// With no input reaching the game the idle timer never resets, so after a few
// seconds FO4 starts its attract-mode camera and orbits the player 360 degrees.
// That happened on the first live test of the panel and this setting was used to
// switch it off.
//
// It then turned out that the orbiting camera was the ONLY camera that shows the
// character's face at all: the free camera does not render the player, so the
// staged view is now AutoVanityState itself, with its orbit angle pinned every
// frame (see chargen_stage). Disabling auto vanity would be disabling the very
// state the editor depends on, and the pin — not the setting — is what stops the
// rotation. Left here as a located offset, deliberately unused.
//
// Located the same way bBackgroundMouse was: find the data word pointing at the
// setting's name string (0x1425A2220), and the Setting object is 0x10 below it
// with its value at +0x08. That lands on byte_142F2E170, RVA 0x2F2E170, which
// holds 0 in a vanilla session.
[[maybe_unused]] constexpr std::uintptr_t DISABLE_AUTOVANITY_RVA = 0x02F2E170;

constexpr std::uintptr_t MENUCURSOR_PTR_RVA = 0x0326F458;
constexpr std::uintptr_t CURSOR_ACQUIRE_RVA = 0x01B1D5B0;   // ++refcount
constexpr std::uintptr_t CURSOR_RELEASE_RVA = 0x01B1D5C0;   // --refcount
using CursorRefFn = void(__fastcall*)(void*);

std::atomic<bool> g_captured{false};

// HOW MANY TIMES WE HAVE INCREMENTED WINDOWS' CURSOR COUNTER, so the release can
// undo precisely that many.
//
// ShowCursor is not a setter, it is a counter: TRUE increments, FALSE decrements,
// and the cursor is drawn while the total is >= 0. The capture used to call
// ShowCursor(TRUE) once on open and ShowCursor(FALSE) once on close, which
// balances -- but the per-frame hold added an uncounted ShowCursor(TRUE) every
// time it found the cursor hidden. The game hides it from its own pump, so those
// extra increments accumulated against a single decrement on release, the total
// stayed positive, and the mouse pointer sat on top of the game after the editor
// had closed and handed input back.
//
// Counting is the whole fix. Whatever we added, we take away.
std::atomic<int> g_cursor_boost{0};

void cursor_show_counted() noexcept {
    ShowCursor(TRUE);
    g_cursor_boost.fetch_add(1, std::memory_order_relaxed);
}

void cursor_unwind() noexcept {
    int n = g_cursor_boost.exchange(0, std::memory_order_relaxed);
    if (n > 1) {
        FW_DBG("[editor] unwinding %d cursor increments - the game had been "
               "re-hiding it while the panel was up", n);
    }
    while (n-- > 0) ShowCursor(FALSE);
}

void poke_u8(std::uintptr_t at, std::uint8_t v) noexcept {
    __try { *reinterpret_cast<volatile std::uint8_t*>(at) = v; }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

void cursor_ref(std::uintptr_t base, bool acquire) noexcept {
    __try {
        void* mc = *reinterpret_cast<void* const*>(base + MENUCURSOR_PTR_RVA);
        if (!mc) return;
        auto fn = reinterpret_cast<CursorRefFn>(
            base + (acquire ? CURSOR_ACQUIRE_RVA : CURSOR_RELEASE_RVA));
        fn(mc);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// Hold the capture, every frame, for as long as the panel is up.
//
// WHY A ONE-SHOT WRITE WAS NEVER GOING TO HOLD. The comment above says it
// outright: the engine's two modal pumps do `{ byte = 0; drain; byte = 1; }`.
// They END by setting the byte back to 1. So the moment any of them runs -- and
// they run constantly -- the byte our capture cleared is 1 again and the game is
// reading the mouse once more. The symptom was a single stray left click landing
// on the character, who then raised a weapon and started turning with the mouse
// while the panel was still open.
//
// This is the same mistake as the collision flag, and it has the same fix: state
// the engine also writes cannot be set once, it has to be re-asserted, and the
// winner is whoever wrote last. Present is the right place because it is once per
// frame after the game's own update.
//
// The cursor is re-asserted through GetCursorInfo rather than by calling
// ShowCursor every frame: ShowCursor keeps an internal counter and a blind
// increment per frame would climb without bound and never unwind on release.
// GetCursorInfo reports visibility without touching that counter, so ShowCursor
// is only called when the cursor has actually been hidden from under us.
void hold_capture(std::uintptr_t module_base) noexcept {
    if (!module_base) return;
    if (!g_captured.load(std::memory_order_acquire)) return;

    __try {
        auto* b = reinterpret_cast<volatile std::uint8_t*>(
            module_base + INPUT_DISPATCH_OK_RVA);
        if (*b != 0) {
            *b = 0;
            static DWORD s_last = 0;
            const DWORD now = GetTickCount();
            if (now - s_last >= 2000) {
                s_last = now;
                FW_DBG("[editor] the engine put the input-dispatch byte back to 1 "
                       "- re-clearing it (throttled to 1/2s)");
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    CURSORINFO ci{};
    ci.cbSize = sizeof(ci);
    if (GetCursorInfo(&ci) && (ci.flags & CURSOR_SHOWING) == 0) {
        cursor_show_counted();
    }
}

}  // namespace

bool input_captured() noexcept {
    return g_captured.load(std::memory_order_acquire);
}

void set_input_captured(std::uintptr_t module_base, bool on) {
    if (!module_base) return;
    if (g_captured.exchange(on, std::memory_order_acq_rel) == on) return;

    if (on) {
        poke_u8(module_base + INPUT_DISPATCH_OK_RVA, 0);
        cursor_ref(module_base, /*acquire=*/true);
        cursor_show_counted();
        FW_LOG("[editor] input captured: dispatch byte cleared, MenuCursor "
               "refcount held, OS cursor shown. The game sees no input while the "
               "panel is up. Auto vanity is deliberately NOT disabled any more - "
               "it is the camera the editor uses, and its orbit is held still by "
               "pinning the angle rather than by switching the mode off.");
    } else {
        poke_u8(module_base + INPUT_DISPATCH_OK_RVA, 1);
        cursor_ref(module_base, /*acquire=*/false);
        cursor_unwind();
        FW_LOG("[editor] input released back to the game");
    }
}

bool wndproc(void* hwnd, unsigned int msg, unsigned long long wparam,
             long long lparam) {
    if (!g_captured.load(std::memory_order_acquire)) return false;
    if (!g_ready.load(std::memory_order_acquire))    return false;

    // WM_SETCURSOR is ours to answer. The engine's own handler always drives the
    // cursor to hidden over the client area — ShowCursor has exactly two call
    // sites in the whole binary and both live in that case — so nothing in the
    // game will ever show it for us. Answer and do NOT chain: the game's case
    // calls DefWindowProc itself and only acts when that returns 0, so chaining
    // after it is too late.
    if (msg == WM_SETCURSOR) {
        SetCursor(LoadCursorW(nullptr, IDC_ARROW));
        return true;
    }

    // NEVER touch the messages that let a user leave. Checked before ImGui gets
    // a look, because ImGui's handler reports some of these as consumed and that
    // would be enough to strand someone in a panel they cannot close.
    switch (msg) {
        case WM_CLOSE: case WM_SYSCOMMAND:
        case WM_SYSKEYDOWN: case WM_SYSKEYUP:
        case WM_ACTIVATE: case WM_ACTIVATEAPP: case WM_KILLFOCUS:
            return false;
        default:
            break;
    }

    if (::ImGui_ImplWin32_WndProcHandler(static_cast<HWND>(hwnd), msg,
                                       static_cast<WPARAM>(wparam),
                                       static_cast<LPARAM>(lparam))) {
        return true;
    }

    // WM_INPUT DIES HERE, and the previous comment explaining why it did not is
    // the record of the mistake.
    //
    // It said WM_INPUT was "left alone deliberately: the engine's dispatch byte
    // already makes its own procedure drop it". That byte cannot win: the
    // engine's modal pumps are shaped `{ byte = 1; drain PeekMessage; byte = 1; }`,
    // so a WM_INPUT is dispatched from INSIDE a pump with the byte already back
    // at 1. Re-asserting the byte once per frame from Present is always too late
    // by construction, not by accident of timing -- and a single stray left click
    // proved it: the character raised a weapon and started turning with the mouse
    // with the panel still open, and the game then swapped the camera out of auto
    // vanity, which is what made the view go crooked and show a first-person arm.
    //
    // Swallowing it here does not race anything, because this subclass sees the
    // message before the game's own procedure does. The old worry was denying raw
    // input to "anything else that might legitimately want it"; while a modal
    // character-creation panel is up, there is nothing else.
    //
    // DefWindowProc is still called, because MSDN requires it for WM_INPUT so the
    // system can release the raw-input buffer. Its return value is meaningless
    // here; what matters is that the game never gets a look.
    if (msg == WM_INPUT) {
        DefWindowProcW(static_cast<HWND>(hwnd), msg,
                       static_cast<WPARAM>(wparam),
                       static_cast<LPARAM>(lparam));
        return true;
    }

    // Swallow the legacy mouse and keyboard messages too, so nothing downstream
    // reacts to them either. WM_INPUT is handled above.
    //
    // WM_SYSKEYDOWN and WM_SYSKEYUP are NOT in this list, and that is the point.
    // An earlier version swallowed them and broke ALT+F4: that combination
    // arrives as WM_SYSKEYDOWN and only becomes WM_SYSCOMMAND/SC_CLOSE after
    // DefWindowProc sees it. The user found it immediately, and it is the worst
    // class of bug an overlay can have — one that takes away the way out. The
    // same reasoning covers ALT+TAB and the system menu. A panel may take the
    // game's input; it may never take the operating system's.
    switch (msg) {
        case WM_MOUSEMOVE: case WM_LBUTTONDOWN: case WM_LBUTTONUP:
        case WM_RBUTTONDOWN: case WM_RBUTTONUP:
        case WM_MBUTTONDOWN: case WM_MBUTTONUP:
        case WM_MOUSEWHEEL:  case WM_MOUSEHWHEEL:
        case WM_KEYDOWN:     case WM_KEYUP:
        case WM_CHAR:
            return true;
        default:
            return false;
    }
}

void on_frame(std::uintptr_t module_base) {
    // THE INPUT CAPTURE FOLLOWS THE FLAG, and it has to be reconciled here --
    // before the early-out -- because releasing it is as important as taking it.
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
    const bool want = fw::native::appearance::editing();
    if (input_captured() != want) set_input_captured(module_base, want);

    // Closed is the common case and must cost nothing. Checked before ImGui is
    // even brought up, so a session that never opens the editor never pays for
    // its initialisation either.
    if (!want) return;

    if (!g_ready.load(std::memory_order_acquire)) {
        if (!try_init(module_base)) return;
    }

    // Before drawing: take the input back off the game. It reclaims it on its
    // own every time one of its modal pumps runs.
    hold_capture(module_base);

    const GameD3D g = game_d3d();
    if (!g.context || !g.backbuf_rtv) return;

    // Build the option lists on the first frame the data handler is
    // populated. Cheap after that: one atomic read.
    cat::build(module_base, appear::read_from_player(module_base).female);
    // The tint catalogue is a separate walk with a separate failure mode: the
    // race's CharGenData is built lazily, so this can legitimately return false
    // for a while after the head parts are already there.
    cat::build_tints(module_base);

    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();
    draw_panel(module_base);
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
    if (!g_ready.exchange(false, std::memory_order_acq_rel)) return;
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    FW_LOG("[editor] ImGui shut down");
}

}  // namespace fw::render::editor
