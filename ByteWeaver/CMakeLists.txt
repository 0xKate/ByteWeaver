# ---- ByteWeaver library ----
add_library(ByteWeaver STATIC)

# Use NEW behavior for download extraction timestamps
cmake_policy(SET CMP0135 NEW)
include(ExternalProject)

target_sources(ByteWeaver PUBLIC
        "src/ByteWeaver.cpp"
        "src/WinDetour.cpp"
        "src/WinPatch.cpp"
        "src/MemoryManager.cpp"
        "src/AddressScanner.cpp"
        "src/AddressEntry.cpp"
        "src/AddressDB.cpp"
)
# ByteWeaver Headers
target_include_directories(ByteWeaver PUBLIC
        "include/"
)

# Export an alias (nice for consumers)
add_library(ByteWeaver::ByteWeaver ALIAS ByteWeaver)