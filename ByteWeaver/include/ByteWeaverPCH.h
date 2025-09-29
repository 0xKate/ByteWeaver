// Copyright(C) 2025 0xKate - MIT License

#pragma once

// Windows API
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// ReSharper disable file CppUnusedIncludeDirective

// STD Lib
#include <array>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#if defined(_WIN64)
    #ifndef ADDR_FMT
        #define ADDR_FMT "0x%016llx"
    #endif
#else
    #ifndef ADDR_FMT
        #define ADDR_FMT "0x%08x"
    #endif
#endif



namespace ByteWeaver {

    namespace fs = std::filesystem;

#if defined(_WIN64)
    constexpr bool WIN64 = true;
#elif defined(_M_IX86)
    constexpr bool WIN64 = false;
#else
    #error "Unknown architecture"
#endif

    #if !defined(LogUtils)
        enum class LogLevel : int {
            LOG_DEBUG,
            LOG_INFO,
            LOG_WARN,
            LOG_ERROR
        };
    // Signature expected for custom loggers
    using LogFunction = void(*)(LogLevel level, const std::string& msg);
    #else
    using LogFunction = void(*)(LogUtils::LogLevel level, const std::string& msg);
    #endif




    inline LogFunction LogCallback = nullptr;
    inline std::mutex LogMutex;

    // Install a custom logger from the outside
    inline void SetLogCallback(const LogFunction fn) {
        LogCallback = fn;
    }

    inline void LogInternal(const int level, const char* fmt, va_list args) {
        char buffer[1024];
        vsnprintf(buffer, sizeof(buffer), fmt, args);

        std::lock_guard lock(LogMutex);
        if (LogCallback) {
            LogCallback(static_cast<LogLevel>(level), buffer);
        }
        else {
            const char* levelStr;
            FILE* output = stdout;

            switch (level) {
            case 0: levelStr = "DEBUG"; break;
            case 1: levelStr = "INFO"; break;
            case 2: levelStr = "WARN"; output = stderr; break;
            case 3: levelStr = "ERROR"; output = stderr; break;
            default: return;
            }

            fprintf(output, "[ByteWeaver][%s] %s\n", levelStr, buffer);
        }
    }

    inline void Debug(const char* fmt, ...) {
        va_list args; va_start(args, fmt);
        LogInternal(0, fmt, args);
        va_end(args);
    }
    inline void Info(const char* fmt, ...) {
        va_list args; va_start(args, fmt);
        LogInternal(1, fmt, args);
        va_end(args);
    }
    inline void Warn(const char* fmt, ...) {
        va_list args; va_start(args, fmt);
        LogInternal(2, fmt, args);
        va_end(args);
    }
    inline void Error(const char* fmt, ...) {
        va_list args; va_start(args, fmt);
        LogInternal(3, fmt, args);
        va_end(args);
    }

}