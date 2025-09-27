cmake_minimum_required(VERSION 3.24)
project(ByteWeaverProject VERSION 0.5.36 LANGUAGES C CXX)

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
add_subdirectory(external/Detours)  # defines target: detours       (and alias Detours::Detours) (IMPORTED GLOBAL) + detours_ep
add_subdirectory(ByteWeaver)        # defines target: ByteWeaver    (and alias ByteWeaver::ByteWeaver)
add_subdirectory(LogUtils)          # defines target: LogUtils      (and alias ByteWeaver::LogUtils)
add_subdirectory(DebugTools)        # defines target: DebugTools    (and alias ByteWeaver::DebugTools)
add_subdirectory(ConsoleLogger)     # defines target: ConsoleLogger (and alias ByteWeaver::ConsoleLogger)

# Ensure detours.lib exists
add_dependencies(ByteWeaver Detours)

# Propagate Detours to consumers automatically
target_link_libraries(ByteWeaver PUBLIC Detours::Detours)

# DebugTools depends on ByteWeaver
target_link_libraries(DebugTools PUBLIC ByteWeaver::ByteWeaver)
add_dependencies(DebugTools ByteWeaver)

# --- Helper function for naming scheme ---
function(set_output_names target_name)
    set_target_properties(${target_name} PROPERTIES
            OUTPUT_NAME_DEBUG           "${target_name}-${ARCH_SUFFIX}-Debug"
            OUTPUT_NAME_RELEASE         "${target_name}-${ARCH_SUFFIX}"
            OUTPUT_NAME_RELWITHDEBINFO  "${target_name}-${ARCH_SUFFIX}-RelWithDebInfo"
            OUTPUT_NAME_MINSIZEREL      "${target_name}-${ARCH_SUFFIX}-MinSizeRel"
    )
endfunction()

# --- Apply to each target ---
set_output_names(ByteWeaver)
set_output_names(LogUtils)
set_output_names(DebugTools)
set_output_names(ConsoleLogger)

# --- Install the libraries ---
include(GNUInstallDirs)
# NOTE:
# - ARCHIVE for .lib/.a (static libs)
# - LIBRARY for .so/.dylib (shared libs)
# - RUNTIME for .dll/.exe on Windows
install(TARGETS ByteWeaver LogUtils DebugTools ConsoleLogger
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# --- Install headers from each project ---
install(DIRECTORY ByteWeaver/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ByteWeaver
        FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")
install(DIRECTORY LogUtils/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/LogUtils
        FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")
install(DIRECTORY DebugTools/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/DebugTools
            FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")
install(DIRECTORY ConsoleLogger/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ConsoleLogger
        FILES_MATCHING PATTERN "*.h" PATTERN "*.rc")