# rexgamejolt - Game Jolt Game API client (trophies, sessions)
#
# Needs an HTTPS backend; only WinHTTP is wired up so far, so the client
# compiles to a no-op elsewhere (see REX_GAMEJOLT_HAVE_HTTP in gamejolt.cpp).

add_library(rexgamejolt OBJECT gamejolt.cpp)
add_library(rex::gamejolt ALIAS rexgamejolt)

target_include_directories(rexgamejolt PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# For "thirdparty/crypto/TinySHA1.hpp" (the optional SHA-1 signature mode).
target_include_directories(rexgamejolt PRIVATE ${PROJECT_SOURCE_DIR})

target_link_libraries(rexgamejolt PUBLIC rexcore tomlplusplus)

if(WIN32)
    target_link_libraries(rexgamejolt PUBLIC winhttp)
endif()
