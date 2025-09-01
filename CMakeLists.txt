cmake_minimum_required(VERSION 3.15)

project(ByteWeaver VERSION 0.2.17 LANGUAGES CXX)

include(FetchContent)     # OK to include even though we use ExternalProject
include(ExternalProject)

set(BASE_TARGET_NAME "ByteWeaver")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(ARCH_SUFFIX "x64")
else()
    set(ARCH_SUFFIX "x86")
endif()

# ---- Detours Library Import ----
set(DETOURS_GIT_REPO "https://github.com/microsoft/Detours.git")
set(DETOURS_GIT_TAG  "v4.0.1")

# Arch mapping for output folder names used by Detours
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(DETOURS_ARCH "X64")
else()
  set(DETOURS_ARCH "X86")
endif()

# Separate clone per-arch to avoid cross-arch collisions
set(DETOURS_ROOT     "${CMAKE_BINARY_DIR}/_deps/detours-${DETOURS_ARCH}")
set(DETOURS_REPO_DIR "${DETOURS_ROOT}")            # repo root after clone
set(DETOURS_BUILDWD  "${DETOURS_REPO_DIR}/src")    # where we run nmake
set(DETOURS_OUT_LIB  "${DETOURS_REPO_DIR}/lib.${DETOURS_ARCH}/detours.lib")
set(DETOURS_OUT_INC  "${DETOURS_REPO_DIR}/include")

# Make the include dir exist now so generator stops complaining
file(MAKE_DIRECTORY "${DETOURS_OUT_INC}")

ExternalProject_Add(detours_ep
  GIT_REPOSITORY      ${DETOURS_GIT_REPO}
  GIT_TAG             ${DETOURS_GIT_TAG}
  GIT_PROGRESS        ON
  UPDATE_DISCONNECTED 1
  SOURCE_DIR          ${DETOURS_REPO_DIR}
  CONFIGURE_COMMAND   ""              # no configure step
  BUILD_IN_SOURCE     1
  # Run nmake from detours/src (official build step)
  BUILD_COMMAND       ${CMAKE_COMMAND} -E chdir ${DETOURS_BUILDWD} nmake
  INSTALL_COMMAND     ""
  LOG_BUILD           1
)

# Wrap the outputs in an IMPORTED target
add_library(detours STATIC IMPORTED GLOBAL)
set_target_properties(detours PROPERTIES
  IMPORTED_LOCATION             "${DETOURS_OUT_LIB}"
  INTERFACE_INCLUDE_DIRECTORIES "${DETOURS_OUT_INC}"
)
add_dependencies(detours detours_ep)


# ---- JSON Lib ----
FetchContent_Declare(
        nlohmann_json
        URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
)
FetchContent_MakeAvailable(nlohmann_json)

# ---- DebugTools library ----
add_library(DebugTools STATIC
    "src/DebugTools.cpp"
)

# DebugTools uses Windows libs (DbgHelp, Psapi), link them here.
if(WIN32)
    target_link_libraries(DebugTools
        PRIVATE
            Dbghelp
            Psapi
            nlohmann_json::nlohmann_json
    )
endif()

# Expose headers
target_include_directories(DebugTools
    PUBLIC
        "external/"
        "include/"
)


# In multi-config IDEs, don't build DebugTools by default for non-Debug configs
# (so Release/RelWithDebInfo/MinSizeRel won't build it unless explicitly selected)
set_target_properties(DebugTools PROPERTIES
    EXCLUDE_FROM_DEFAULT_BUILD_Release TRUE
    EXCLUDE_FROM_DEFAULT_BUILD_RelWithDebInfo TRUE
    EXCLUDE_FROM_DEFAULT_BUILD_MinSizeRel TRUE
)

# ---- ByteWeaver library ----
add_library(ByteWeaver STATIC
        "src/ByteWeaver.cpp"
        "src/WinDetour.cpp"
        "src/WinPatch.cpp"
        "src/MemoryManager.cpp"
        "src/AddressScanner.cpp"
        "src/AddressEntry.cpp"
        "src/AddressDB.cpp"
)



target_link_libraries(ByteWeaver PRIVATE nlohmann_json::nlohmann_json)

# ByteWeaver Headers 
target_include_directories(ByteWeaver PUBLIC
        "external/"
        "include/"
)

# Link Detours always
target_link_libraries(ByteWeaver PRIVATE detours)

# Link DebugTools only for Debug configuration
target_link_libraries(ByteWeaver
    PUBLIC
        $<$<CONFIG:Debug>:DebugTools>
)


set_target_properties(ByteWeaver PROPERTIES
    OUTPUT_NAME_DEBUG "${BASE_TARGET_NAME}-${ARCH_SUFFIX}-Debug"
    OUTPUT_NAME_RELEASE "${BASE_TARGET_NAME}-${ARCH_SUFFIX}"
    OUTPUT_NAME_RELWITHDEBINFO "${BASE_TARGET_NAME}-${ARCH_SUFFIX}-RelWithDebInfo"
    OUTPUT_NAME_MINSIZEREL "${BASE_TARGET_NAME}-${ARCH_SUFFIX}-MinSizeRel"
)

# ---- Install rules ----
install(TARGETS ByteWeaver
    ARCHIVE DESTINATION lib
)

# Install DebugTools archive only for Debug builds
install(TARGETS DebugTools
    CONFIGURATIONS Debug
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/ DESTINATION include)
