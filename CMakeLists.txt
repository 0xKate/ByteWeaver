cmake_minimum_required(VERSION 3.15)

project(ByteWeaver VERSION 0.0.1 LANGUAGES CXX)


# Enable Edit and Continue for MSVC (optional)
if(POLICY CMP0141)
    cmake_policy(SET CMP0141 NEW)
    set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()


set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- ByteWeaver library ----

add_library(ByteWeaver STATIC
    "include/ByteWeaver.h"
    "src/ByteWeaver.cpp"
    "include/WinDetour.h"
    "src/WinDetour.cpp"
    "include/WinPatch.h"
    "src/WinPatch.cpp"    
)

target_include_directories(ByteWeaver PUBLIC
    "external/detours"  # for detours.h
    "include/"
)

target_precompile_headers(ByteWeaver PRIVATE
    "<PCH.h>"
)

# Select the right .lib based on architecture
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    # 64-bit
    set(DETOURS_LIB_PATH "external/detours/lib/x64/detours.lib")
else()
    # 32-bit
    set(DETOURS_LIB_PATH "external/detours/lib/x86/detours.lib")
endif()

# Add the library to your target
target_link_libraries(ByteWeaver PRIVATE "${DETOURS_LIB_PATH}")


# Optional: define that you're linking statically
target_compile_definitions(ByteWeaver PRIVATE DETOURS_STATIC
    $<$<CONFIG:Debug>:BYTEWEAVER_ENABLE_LOGGING=1>
    $<$<CONFIG:Release>:BYTEWEAVER_ENABLE_LOGGING=0>)

# Optional install (if you plan to distribute headers & lib)
install(TARGETS ByteWeaver
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY src/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)
