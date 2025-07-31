

#pragma once

#include "PCH.h"

#if defined(_M_X64)
constexpr bool Is64Bit = true;
#elif defined(_M_IX86)
constexpr bool Is64Bit = false;
#else
#error "Unknown architecture"
#endif

#ifndef BYTEWEAVER_ENABLE_LOGGING
#define BYTEWEAVER_ENABLE_LOGGING 0
#endif

#if BYTEWEAVER_ENABLE_LOGGING
constexpr bool ENABLE_DETOUR_LOGGING = true;
constexpr bool ENABLE_PATCH_LOGGING = true;

#else
constexpr bool ENABLE_DETOUR_LOGGING = false;
constexpr bool ENABLE_PATCH_LOGGING = false;
#endif

namespace fs = std::filesystem;


namespace ByteWeaver {
    // Signature expected for custom loggers
    using LogFunction = void(*)(int level, const char* msg);

    // Install a custom logger from the outside
    void SetLogCallback(LogFunction fn);

    // Your internal logging functions
    void debug(const char* fmt, ...);
    void info(const char* fmt, ...);
    void warn(const char* fmt, ...);
    void error(const char* fmt, ...);
}