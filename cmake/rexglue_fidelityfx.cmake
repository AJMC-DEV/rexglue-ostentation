# rexglue_fidelityfx.cmake — Optional AMD FidelityFX integration via FetchContent
#
# Expects REXGLUE_ENABLE_FIDELITYFX to be set before inclusion.
# On success, creates amd_fidelityfx_vk and/or amd_fidelityfx_dx12 targets
# and sets REXGLUE_FIDELITYFX_SOURCE_DIR to the fetched SDK root.

if(NOT REXGLUE_ENABLE_FIDELITYFX)
    return()
endif()

# ── Dependency validation ────────────────────────────────────────────────
if(NOT WIN32)
    find_package(Vulkan QUIET)
    if(NOT Vulkan_FOUND)
        message(WARNING
            "REXGLUE_ENABLE_FIDELITYFX requires the Vulkan SDK but it was not found.\n"
            "Install the LunarG Vulkan SDK: https://vulkan.lunarg.com/sdk/home\n"
            "Disabling FidelityFX.")
        set(REXGLUE_ENABLE_FIDELITYFX OFF CACHE BOOL "" FORCE)
        return()
    elseif(Vulkan_VERSION VERSION_LESS "1.3.250")
        message(WARNING
            "REXGLUE_ENABLE_FIDELITYFX requires Vulkan SDK >= 1.3.250 "
            "(found ${Vulkan_VERSION}).\n"
            "Update via: https://vulkan.lunarg.com/sdk/home\n"
            "Disabling FidelityFX.")
        set(REXGLUE_ENABLE_FIDELITYFX OFF CACHE BOOL "" FORCE)
        return()
    else()
        find_program(_rexglue_glslc glslc)
        find_program(_rexglue_glslang glslangValidator)
        if(NOT _rexglue_glslc AND NOT _rexglue_glslang)
            message(WARNING
                "REXGLUE_ENABLE_FIDELITYFX requires Vulkan shader tools "
                "(glslc or glslangValidator) but neither was found.\n"
                "Install the full LunarG Vulkan SDK: https://vulkan.lunarg.com/sdk/home\n"
                "Disabling FidelityFX.")
            set(REXGLUE_ENABLE_FIDELITYFX OFF CACHE BOOL "" FORCE)
            unset(_rexglue_glslc CACHE)
            unset(_rexglue_glslang CACHE)
            return()
        endif()
        unset(_rexglue_glslc CACHE)
        unset(_rexglue_glslang CACHE)
    endif()
endif()

# ── Fetch FidelityFX SDK ─────────────────────────────────────────────────
include(FetchContent)
FetchContent_Declare(
    fidelityfx
    GIT_REPOSITORY https://github.com/rexglue/FidelityFX-SDK.git
    GIT_TAG        eee08db1688ac3d1275a70b728f4a8ba22914213
    GIT_SHALLOW    OFF
)
FetchContent_GetProperties(fidelityfx)
if(NOT fidelityfx_POPULATED)
    FetchContent_Populate(fidelityfx)
endif()

# ── Workaround: convert UTF-16 .rc files to UTF-8 ────────────────────────
# Upstream FidelityFX ships some Windows resource scripts (e.g.
# ffx-api/src/resource/ffx_api_dll.rc) encoded as UTF-16 LE with a BOM.
# `llvm-rc` (used by clang on Windows) rejects UTF-16 with:
#   "fatal error: UTF-16 (LE) byte order mark detected ..."
# Rewrite any such file in place as UTF-8 so the build succeeds with clang.
file(GLOB_RECURSE _rexglue_ffx_rc_files
    "${fidelityfx_SOURCE_DIR}/*.rc")
foreach(_rc IN LISTS _rexglue_ffx_rc_files)
    file(READ "${_rc}" _rc_head LIMIT 2 HEX)
    # UTF-16 LE BOM = 0xFF 0xFE
    if(_rc_head STREQUAL "fffe")
        message(STATUS "rexglue: converting UTF-16 .rc to UTF-8: ${_rc}")
        file(STRINGS "${_rc}" _rc_lines ENCODING UTF-8)
        set(_rc_text "")
        foreach(_line IN LISTS _rc_lines)
            string(APPEND _rc_text "${_line}\n")
        endforeach()
        file(WRITE "${_rc}" "${_rc_text}")
    endif()
endforeach()
unset(_rexglue_ffx_rc_files)

set(REXGLUE_FIDELITYFX_SOURCE_DIR "${fidelityfx_SOURCE_DIR}" CACHE INTERNAL
    "Root of the fetched FidelityFX SDK source tree")

# ── Backend selection ────────────────────────────────────────────────────
set(REXGLUE_FIDELITYFX_BACKEND "auto" CACHE STRING
    "FidelityFX backend to build (auto, vk, dx12)")
set_property(CACHE REXGLUE_FIDELITYFX_BACKEND PROPERTY STRINGS auto vk dx12)
set(_rexglue_fidelityfx_backend "${REXGLUE_FIDELITYFX_BACKEND}")
string(TOLOWER "${_rexglue_fidelityfx_backend}" _rexglue_fidelityfx_backend)

if(_rexglue_fidelityfx_backend STREQUAL "auto")
    if(WIN32 AND REXGLUE_USE_D3D12)
        set(_rexglue_fidelityfx_backend "dx12")
    elseif(REXGLUE_USE_VULKAN)
        set(_rexglue_fidelityfx_backend "vk")
    elseif(REXGLUE_USE_D3D12)
        set(_rexglue_fidelityfx_backend "dx12")
    endif()
endif()

if(_rexglue_fidelityfx_backend STREQUAL "vk")
    if(NOT REXGLUE_USE_VULKAN)
        message(FATAL_ERROR
            "REXGLUE_FIDELITYFX_BACKEND=vk requires REXGLUE_USE_VULKAN=ON")
    endif()
    set(FFX_API_BACKEND VK_X64 CACHE STRING "" FORCE)
elseif(_rexglue_fidelityfx_backend STREQUAL "dx12")
    if(NOT REXGLUE_USE_D3D12)
        message(FATAL_ERROR
            "REXGLUE_FIDELITYFX_BACKEND=dx12 requires REXGLUE_USE_D3D12=ON")
    endif()
    set(FFX_API_BACKEND DX12_X64 CACHE STRING "" FORCE)
elseif(_rexglue_fidelityfx_backend STREQUAL "")
    message(FATAL_ERROR "FidelityFX requires a supported graphics backend")
else()
    message(FATAL_ERROR
        "Invalid REXGLUE_FIDELITYFX_BACKEND='${REXGLUE_FIDELITYFX_BACKEND}' "
        "(expected auto, vk, or dx12)")
endif()

if(REXGLUE_USE_VULKAN AND REXGLUE_USE_D3D12)
    message(STATUS
        "FidelityFX backend selected for this build: ${_rexglue_fidelityfx_backend}")
endif()

# ── Build FidelityFX ─────────────────────────────────────────────────────
set(FFX_API_ENABLE_FRAMEGEN_PROVIDER OFF CACHE BOOL "" FORCE)
# Disable upstream auto shader compilation. On Windows the FXC permutation
# build for FSR3 hangs indefinitely under CI (observed >50 min with no
# progress on GitHub Actions). The libs link without prebaked shaders;
# anything that needs them can be compiled separately.
set(FFX_API_AUTO_COMPILE_SHADERS OFF CACHE BOOL "" FORCE)
add_subdirectory("${fidelityfx_SOURCE_DIR}/ffx-api" "${fidelityfx_BINARY_DIR}/ffx-api" EXCLUDE_FROM_ALL)

# The upstream FidelityFX targets expose source-tree include paths in
# INTERFACE_INCLUDE_DIRECTORIES, which breaks our install export checks.
# We only link against these targets internally, so no public includes are
# needed on the exported interface.
if(TARGET amd_fidelityfx_vk)
    set_target_properties(amd_fidelityfx_vk PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ""
    )
endif()
if(TARGET amd_fidelityfx_dx12)
    set_target_properties(amd_fidelityfx_dx12 PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ""
    )
endif()

# FidelityFX's toolchain.cmake force-sets CMAKE_GENERATOR_PLATFORM (for VS generators).
# With Ninja this variable is invalid and poisons every subsequent try_compile() call.
# Clear it from the cache.
unset(CMAKE_GENERATOR_PLATFORM CACHE)
