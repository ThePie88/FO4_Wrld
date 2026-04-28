cmake_minimum_required(VERSION 3.25)
project(fw_native LANGUAGES CXX)

# Fallout 4 next-gen is /arch:AVX2 only, and we share its process space.
# Sticking to the same instruction set avoids ABI surprises.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# MinHook — vendored in deps/MinHook/ (git submodule or clone). Static
# build as part of our DLL; no redistribution concern.
add_subdirectory(deps/MinHook EXCLUDE_FROM_ALL)

# Proxy DLL. The Windows loader picks up `dxgi.dll` in the game root
# BEFORE hitting C:\Windows\System32, so our file name must match exactly.
add_library(fw_native SHARED
    src/dll_main.cpp
    src/proxy_exports.cpp
    src/log.cpp
    src/version.cpp
    src/hook_manager.cpp
    src/main_thread_dispatch.cpp
    src/ref_identity.cpp
    src/hooks/install_all.cpp
    src/hooks/kill_hook.cpp
    src/hooks/container_hook.cpp
    src/hooks/put_hook.cpp
    src/hooks/pickup_hook.cpp
    src/hooks/player_pos_hook.cpp
    src/hooks/main_menu_hook.cpp
    src/hooks/worldstate_hook.cpp
    src/hooks/door_hook.cpp         # B6.1: SetOpenState mutator observation
    src/hooks/equip_cycle.cpp       # B8  : post-LoadGame BipedAnim normalize
    src/hooks/engine_tracer.cpp     # M6.3: native NIF-load path observation
    src/net/udp_socket.cpp
    src/net/reliable.cpp
    src/net/client.cpp
    src/config.cpp
    src/engine/engine_calls.cpp
    src/render/present_hook.cpp
    src/render/triangle_render.cpp
    src/render/body_render.cpp      # Path A archived, compiled but not invoked
    src/render/dsv_capture.cpp      # Path A archived, compiled but not invoked
    src/render/scene_render_hook.cpp  # β.6: hook 3D scene walker (reserved)
    src/render/vp_capture.cpp         # β.6: capture real scene VP (sub_1421DC480)
    src/render/head_placeholder.cpp   # β.6: procedural sphere head until real mesh
    src/assets/fwn_loader.cpp       # Path A archived, compiled but not invoked
    src/ghost/actor_hijack.cpp      # Path B ghost pipeline
    src/native/scene_inject.cpp     # Strada B M1: native scene graph injection
    src/native/scene_walker.cpp     # Strada B M2.1: diagnostic scene graph walker
    src/native/skin_rebind.cpp      # M8P3 step 1: BSSkin::Instance diagnostic walker
)

target_link_libraries(fw_native PRIVATE minhook)

set_target_properties(fw_native PROPERTIES
    OUTPUT_NAME "dxgi"
    PREFIX ""
    SUFFIX ".dll"
)

# Export only the 3 real dxgi factory entry points via the .def file.
# No __declspec(dllexport) in the source — the .def is the single source of
# truth for what we advertise, so there's no chance of name mangling surprises.
target_link_options(fw_native PRIVATE
    "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/dxgi.def"
)

target_compile_options(fw_native PRIVATE
    /arch:AVX2        # match FO4 NG instruction set
    /W4
    /permissive-
    /EHsc
    /Zc:__cplusplus
    /utf-8
    # Release-only guards; CMake's Release config already adds /O2 /DNDEBUG
)

target_compile_definitions(fw_native PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
    _CRT_SECURE_NO_WARNINGS
)

# Explicit system imports — WIN32_LEAN_AND_MEAN trims some.
# d3d11 added for B5 Step 1 (Present hook via kiero-style vtable capture).
# d3dcompiler added for B5 Step 2 (runtime HLSL compile via D3DCompile).
# NOT linking dxgi.lib: our output is dxgi.dll so MSVC emits dxgi.lib as
# import library, which would collide at link time with the system
# dxgi.lib (LNK1149). We don't actually need dxgi.lib because all
# IDXGI* usage in present_hook.cpp is via COM vtable (vtable[8]
# extraction) — no static symbols from the dxgi import library are
# referenced. D3D11CreateDeviceAndSwapChain is in d3d11.lib.
target_link_libraries(fw_native PRIVATE kernel32 user32 version d3d11 d3dcompiler)

# Visible build summary
add_custom_command(TARGET fw_native POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "[fw_native] built: $<TARGET_FILE:fw_native>"
    COMMAND ${CMAKE_COMMAND} -E echo "[fw_native] deploy with: deploy.bat"
)
