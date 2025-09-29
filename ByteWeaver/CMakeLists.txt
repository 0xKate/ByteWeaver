# ---- ByteWeaver library ----
add_library(ByteWeaver STATIC)

target_precompile_headers(ByteWeaver PRIVATE
        include/ByteWeaverPCH.h
)

# ByteWeaver Headers
target_include_directories(ByteWeaver PUBLIC
        include/
)

target_sources(ByteWeaver PUBLIC
        src/AddressDB.cpp
        src/AddressEntry.cpp
        src/AddressScanner.cpp
        src/MemoryManager.cpp
        src/WinDetour.cpp
        src/WinPatch.cpp
)

# Export an alias (nice for consumers)
add_library(ByteWeaver::ByteWeaver ALIAS ByteWeaver)