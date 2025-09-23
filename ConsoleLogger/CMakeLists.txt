# ---- ConsoleLogger ----
add_executable(ConsoleLogger  src/ConsoleLogger.cpp)

target_include_directories(ConsoleLogger PUBLIC
        "include/"
)

# Resolve full path from a relative path
set(APP_ICON_PATH "${PROJECT_SOURCE_DIR}/ConsoleLogger/resources/icon.ico")

# Make it available to C++
target_compile_definitions(ConsoleLogger PRIVATE
        APP_ICON_PATH="${APP_ICON_PATH}"
)

# Configure the .rc file at build time
configure_file(${PROJECT_SOURCE_DIR}/ConsoleLogger/src/ConsoleLogger.rc.in
        ${CMAKE_BINARY_DIR}/ConsoleLogger.rc @ONLY)

if (WIN32)
    target_sources(ConsoleLogger PRIVATE ${CMAKE_BINARY_DIR}/ConsoleLogger.rc)
endif()

# Export an alias (nice for consumers)
add_executable(ByteWeaver::ConsoleLogger ALIAS ConsoleLogger)