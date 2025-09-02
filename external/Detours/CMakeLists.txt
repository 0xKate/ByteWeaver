cmake_minimum_required(VERSION 3.24)
include(ExternalProject)

# ---- Detours repo + arch mapping ----
set(DETOURS_GIT_REPO "https://github.com/microsoft/Detours.git")
set(DETOURS_GIT_TAG  "v4.0.1")

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(DETOURS_ARCH "X64")
else()
    set(DETOURS_ARCH "X86")
endif()

# Per-arch checkout to avoid collisions if you build both x86/x64
set(DETOURS_ROOT     "${CMAKE_BINARY_DIR}/_deps/detours-${DETOURS_ARCH}")
set(DETOURS_REPO_DIR "${DETOURS_ROOT}")
set(DETOURS_BUILDWD  "${DETOURS_REPO_DIR}/src")
set(DETOURS_OUT_LIB  "${DETOURS_REPO_DIR}/lib.${DETOURS_ARCH}/detours.lib")
set(DETOURS_OUT_INC  "${DETOURS_REPO_DIR}/include")

file(MAKE_DIRECTORY "${DETOURS_OUT_INC}")

ExternalProject_Add(detours_ep
        GIT_REPOSITORY      ${DETOURS_GIT_REPO}
        GIT_TAG             ${DETOURS_GIT_TAG}
        GIT_PROGRESS        ON
        UPDATE_DISCONNECTED 1
        SOURCE_DIR          ${DETOURS_REPO_DIR}
        CONFIGURE_COMMAND   ""            # no configure step
        BUILD_IN_SOURCE     1
        BUILD_COMMAND       ${CMAKE_COMMAND} -E chdir ${DETOURS_BUILDWD} nmake
        INSTALL_COMMAND     ""
        LOG_BUILD           1
)

# Imported target other targets can link to
add_library(Detours STATIC IMPORTED GLOBAL)
set_target_properties(Detours PROPERTIES
        IMPORTED_LOCATION             "${DETOURS_OUT_LIB}"
        INTERFACE_INCLUDE_DIRECTORIES "${DETOURS_OUT_INC}"
)
add_dependencies(Detours detours_ep)

# Nice namespaced alias
add_library(Detours::Detours ALIAS Detours)
