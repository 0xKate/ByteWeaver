# ---- ByteWeaver library ----
add_library(LogUtils STATIC)

if(TARGET ByteWeaver)
    target_link_libraries(LogUtils PUBLIC ByteWeaver::ByteWeaver)
    target_compile_definitions(LogUtils PUBLIC HAVE_BYTEWEAVER)
endif()

target_sources(LogUtils PUBLIC
        "src/FileManager.cpp"
        "src/Logger.cpp"
        "src/RemoteConsole.cpp"
)

target_include_directories(LogUtils PUBLIC
        "include/"
)

add_library(ByteWeaver::LogUtils ALIAS LogUtils)