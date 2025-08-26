/*
    Copyright(C) 2025 0xKate

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files(the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions :

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.

    --- Additional Use and Security Notice---

    This software is provided for educational, research, debugging, and authorized
    development purposes only.

    You may not use this software to interfere with or compromise the security,
    integrity, or functionality of systems, networks, software, or services
    without the explicit authorization of their rightful owners.

    Use of this software in contexts such as cheating in online games,
    unauthorized penetration testing, reverse engineering of proprietary systems
    without consent, or any illegal activity is strictly prohibited.

    By using or distributing this software, you agree to comply with all
    applicable laws and to use it only in ethical and lawful ways.
*/

#pragma once

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>  // For MAX_PATH and Windows API calls
#else
#include <climits>    // For PATH_MAX on Linux/Unix
#include <unistd.h>   // For readlink and getpid
#endif

#include <TlHelp32.h>

// STD Lib
#include <string>
#include <filesystem>
#include <vector>
#include <cstdint>
#include <optional>
#include <mutex>
#include <map>
#include <iostream>
#include <thread>
#include <sstream>
#include <fstream>
#include <cstdarg>
#include <cstdio>
#include <unordered_map>
#include <utility> 

#ifndef BYTEWEAVER_ENABLE_LOGGING
#define BYTEWEAVER_ENABLE_LOGGING 0
#endif

namespace ByteWeaver {

    namespace fs = std::filesystem;

    #if defined(_M_X64)
    constexpr bool Is64Bit = true;
    #elif defined(_M_IX86)
    constexpr bool Is64Bit = false;
    #else
    #error "Unknown architecture"
    #endif

    #if BYTEWEAVER_ENABLE_LOGGING
    constexpr bool ENABLE_DETOUR_LOGGING = true;
    constexpr bool ENABLE_PATCH_LOGGING = true;

    #else
    constexpr bool ENABLE_DETOUR_LOGGING = false;
    constexpr bool ENABLE_PATCH_LOGGING = false;
    #endif

    // Signature expected for custom loggers
    using LogFunction = void(*)(int level, const char* msg);

    // Install a custom logger from the outside
    void SetLogCallback(LogFunction fn);

    void debug(const char* fmt, ...);
    void info(const char* fmt, ...);
    void warn(const char* fmt, ...);
    void error(const char* fmt, ...);
}