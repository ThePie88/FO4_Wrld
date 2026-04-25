cmake_minimum_required(VERSION 3.20)
project(fw_launcher LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# MSVC: Unicode entry point (wWinMain/wmain), reasonable warnings.
if(MSVC)
    add_compile_options(/W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc)
    add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
endif()

add_executable(FoM src/main.cpp)
set_target_properties(FoM PROPERTIES
    OUTPUT_NAME "FoM"
    WIN32_EXECUTABLE OFF   # console app — we print progress to stdout
)

# Link-time: nothing exotic, just ensure wmain entry is selected.
if(MSVC)
    target_link_options(FoM PRIVATE /ENTRY:wmainCRTStartup)
endif()

add_custom_command(TARGET FoM POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "[fw_launcher] built: $<TARGET_FILE:FoM>")
