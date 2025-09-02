add_library(DebugTools STATIC)

target_sources(DebugTools PRIVATE src/DebugTools.cpp)

target_include_directories(DebugTools PUBLIC include/)

add_library(ByteWeaver::DebugTools ALIAS DebugTools)
