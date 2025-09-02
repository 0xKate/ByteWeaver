# ---- ByteWeaver library ----
add_library(LogUtils STATIC
        include/Shared.h)

target_sources(LogUtils PUBLIC
        "src/FileManager.cpp"
        "src/Logger.cpp"
        "src/RemoteConsole.cpp"
)

target_include_directories(LogUtils PUBLIC
        "include/"
)

add_library(ByteWeaver::LogUtils ALIAS LogUtils)