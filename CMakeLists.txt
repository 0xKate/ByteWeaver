cmake_minimum_required(VERSION 3.15)

project(ByteWeaver VERSION 0.1.3 LANGUAGES CXX)

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

set(DETOURS_LIB_PATH "external/detours/lib/"ARCH_SUFFIX"/detours.lib")

# ---- ByteWeaver library ----

add_library(ByteWeaver STATIC
    "src/ByteWeaver.cpp"
    "src/WinDetour.cpp"
    "src/WinPatch.cpp"
    "src/MemoryManager.cpp"
    "src/AddressScanner.cpp"
    "src/AddressEntry.cpp"
    "src/AddressDB.cpp"
    "src/DebugTools.cpp"
)

target_include_directories(ByteWeaver PUBLIC
    "external/detours"
    "include/"
)

target_link_libraries(ByteWeaver PRIVATE "${DETOURS_LIB_PATH}")

target_compile_definitions(ByteWeaver PRIVATE DETOURS_STATIC
    $<$<CONFIG:Debug>:BYTEWEAVER_ENABLE_LOGGING=1>
    $<$<CONFIG:Release>:BYTEWEAVER_ENABLE_LOGGING=0>
)

set_target_properties(ByteWeaver PROPERTIES
    OUTPUT_NAME_DEBUG "${BASE_TARGET_NAME}-${ARCH_SUFFIX}-Debug"
    OUTPUT_NAME_RELEASE "${BASE_TARGET_NAME}-${ARCH_SUFFIX}"
    OUTPUT_NAME_RELWITHDEBINFO "${BASE_TARGET_NAME}-${ARCH_SUFFIX}-RelWithDebInfo"
    OUTPUT_NAME_MINSIZEREL "${BASE_TARGET_NAME}-${ARCH_SUFFIX}-MinSizeRel"
)

install(TARGETS ByteWeaver
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/ DESTINATION include)
