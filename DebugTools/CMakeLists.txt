add_library(DebugTools STATIC)

target_sources(DebugTools PUBLIC src/DebugTools.cpp include/ModuleTools.hpp)

target_include_directories(DebugTools PUBLIC include/)

add_library(ByteWeaver::DebugTools ALIAS DebugTools)
