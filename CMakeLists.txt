cmake_minimum_required(VERSION 3.15)

project(ByteWeaver VERSION 0.2.14 LANGUAGES CXX)

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

set(DETOURS_LIB_PATH "external/detours/lib/${ARCH_SUFFIX}/detours.lib")

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
    )
endif()

# Expose headers
target_include_directories(DebugTools
    PUBLIC
        "include/"
)

# per-config defines for DebugTools 
target_compile_definitions(DebugTools
    PRIVATE
        $<$<CONFIG:Debug>:BYTEWEAVER_ENABLE_LOGGING=1>
        $<$<CONFIG:Release>:BYTEWEAVER_ENABLE_LOGGING=0>
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

target_include_directories(ByteWeaver PUBLIC
    "external/detours/include/"
    "include/"
)

# Link Detours always
target_link_libraries(ByteWeaver PUBLIC "${DETOURS_LIB_PATH}")

# Link DebugTools only for Debug configuration
target_link_libraries(ByteWeaver
    PUBLIC
        $<$<CONFIG:Debug>:DebugTools>
)

target_compile_definitions(ByteWeaver PUBLIC DETOURS_STATIC
    $<$<CONFIG:Debug>:BYTEWEAVER_ENABLE_LOGGING=1>
    $<$<CONFIG:Release>:BYTEWEAVER_ENABLE_LOGGING=0>
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
