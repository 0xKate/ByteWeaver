cmake_minimum_required(VERSION 3.24)
project(ByteWeaverProject VERSION 0.3.22 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Arch suffix for output names
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(ARCH_SUFFIX "x64")
else()
    set(ARCH_SUFFIX "x86")
endif()

# --- Subprojects ---
add_subdirectory(external/Detours)  # defines target: detours, (and alias Detours::Detours) (IMPORTED GLOBAL) + detours_ep
add_subdirectory(ByteWeaver)        # defines target: ByteWeaver (and alias ByteWeaver::ByteWeaver)
add_subdirectory(LogUtils)          # defines target: LogUtils (and alias ByteWeaver::LogUtils)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_subdirectory(DebugTools)  # defines target DebugTools
endif()

# Ensure detours.lib exists
add_dependencies(ByteWeaver Detours)

# Propagate Detours to consumers automatically
target_link_libraries(ByteWeaver PUBLIC Detours::Detours)

# DebugTools depends on ByteWeaver
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_link_libraries(DebugTools PRIVATE ByteWeaver::ByteWeaver)
endif()

# --- Output names for ByteWeaver ---
set_target_properties(ByteWeaver PROPERTIES
        OUTPUT_NAME_DEBUG           "ByteWeaver-${ARCH_SUFFIX}-Debug"
        OUTPUT_NAME_RELEASE         "ByteWeaver-${ARCH_SUFFIX}"
        OUTPUT_NAME_RELWITHDEBINFO  "ByteWeaver-${ARCH_SUFFIX}-RelWithDebInfo"
        OUTPUT_NAME_MINSIZEREL      "ByteWeaver-${ARCH_SUFFIX}-MinSizeRel"
)

# --- Output names for LogUtils ---
set_target_properties(LogUtils PROPERTIES
        OUTPUT_NAME_DEBUG           "LogUtils-${ARCH_SUFFIX}-Debug"
        OUTPUT_NAME_RELEASE         "LogUtils-${ARCH_SUFFIX}"
        OUTPUT_NAME_RELWITHDEBINFO  "LogUtils-${ARCH_SUFFIX}-RelWithDebInfo"
        OUTPUT_NAME_MINSIZEREL      "LogUtils-${ARCH_SUFFIX}-MinSizeRel"
)

# --- Output names for DebugTools ---
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set_target_properties(DebugTools PROPERTIES
            OUTPUT_NAME_DEBUG           "DebugTools-${ARCH_SUFFIX}-Debug"
            OUTPUT_NAME_RELEASE         "DebugTools-${ARCH_SUFFIX}"
            OUTPUT_NAME_RELWITHDEBINFO  "DebugTools-${ARCH_SUFFIX}-RelWithDebInfo"
            OUTPUT_NAME_MINSIZEREL      "DebugTools-${ARCH_SUFFIX}-MinSizeRel"
    )
endif()

include(GNUInstallDirs)

# --- Install the libraries ---
# NOTE:
# - ARCHIVE for .lib/.a (static libs)
# - LIBRARY for .so/.dylib (shared libs)
# - RUNTIME for .dll/.exe on Windows
install(TARGETS ByteWeaver LogUtils
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    install(TARGETS DebugTools
            CONFIGURATIONS Debug
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
endif()

# --- Install headers from each project ---
install(DIRECTORY ByteWeaver/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ByteWeaver
        FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")
install(DIRECTORY LogUtils/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/LogUtils
        FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    install(DIRECTORY DebugTools/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/DebugTools
            FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")
endif()

