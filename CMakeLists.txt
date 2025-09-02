cmake_minimum_required(VERSION 3.24)
project(ByteWeaverProject VERSION 0.3.18 LANGUAGES C CXX)


set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Optional LogUtils
option(ENABLE_LOGUTILS "Build and link LogUtils as an optional extension" ON)

set(BASE_TARGET_NAME "ByteWeaver")

# Arch suffix for output names
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(ARCH_SUFFIX "x64")
else()
    set(ARCH_SUFFIX "x86")
endif()

# --- Subprojects ---
add_subdirectory(external/Detours) # defines target: detours, detours_ep (and alias Detours::Detours)

add_subdirectory(ByteWeaver)   # defines target: ByteWeaver (and alias ByteWeaver::ByteWeaver)
add_subdirectory(DebugTools)   # defines target: DebugTools (and alias ByteWeaver::DebugTools)

if(ENABLE_LOGUTILS)
    add_subdirectory(LogUtils)   # defines target: LogUtils (and alias ByteWeaver::LogUtils)
endif()

# --- Linkage ---
# ByteWeaver depends on Detours
target_link_libraries(ByteWeaver PUBLIC Detours::Detours)

# DebugTools depends on ByteWeaver
target_link_libraries(DebugTools PRIVATE ByteWeaver::ByteWeaver)

# ByteWeaver optionally depends on LogUtils
if(ENABLE_LOGUTILS AND TARGET LogUtils)
    target_link_libraries(ByteWeaver PRIVATE ByteWeaver::LogUtils)
    target_compile_definitions(ByteWeaver PRIVATE BW_WITH_LOGUTILS=1)
endif()

# --- Output names for ByteWeaver (customize others similarly if desired) ---
set_target_properties(ByteWeaver PROPERTIES
        OUTPUT_NAME_DEBUG         "${BASE_TARGET_NAME}-${ARCH_SUFFIX}-Debug"
        OUTPUT_NAME_RELEASE       "${BASE_TARGET_NAME}-${ARCH_SUFFIX}"
        OUTPUT_NAME_RELWITHDEBINFO "${BASE_TARGET_NAME}-${ARCH_SUFFIX}-RelWithDebInfo"
        OUTPUT_NAME_MINSIZEREL    "${BASE_TARGET_NAME}-${ARCH_SUFFIX}-MinSizeRel"
)

include(GNUInstallDirs)

# --- Install the libraries ---
# NOTE:
# - ARCHIVE for .lib/.a (static libs)
# - LIBRARY for .so/.dylib (shared libs)
# - RUNTIME for .dll/.exe on Windows
install(TARGETS ByteWeaver DebugTools
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# LogUtils is optional – install it only if it was built
if (TARGET LogUtils)
    install(TARGETS LogUtils
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
endif()

# --- Install headers from each project ---
install(DIRECTORY ByteWeaver/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ByteWeaver
        FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")
install(DIRECTORY DebugTools/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/DebugTools
        FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")
if (TARGET LogUtils)
    install(DIRECTORY LogUtils/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/LogUtils
            FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")
endif()

