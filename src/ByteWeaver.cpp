// Copyright(C) 2025 0xKate - MIT License

#include "ByteWeaver.h"

#include <cstdarg>
#include <cstdio>
#include <mutex>

namespace ByteWeaver {

    static LogFunction logCallback = nullptr;
    static std::mutex logMutex;

    void SetLogCallback(LogFunction fn) {
        logCallback = fn;
    }

    static void log_internal(int level, const char* fmt, va_list args) {
        char buffer[1024];
        vsnprintf(buffer, sizeof(buffer), fmt, args);

        std::lock_guard<std::mutex> lock(logMutex);
        if (logCallback) {
            logCallback(level, buffer);
        }
        else {
            // default fallback
            const char* levelStr = nullptr;
            switch (level) {
            case 0: levelStr = "DEBUG"; break;
            case 1:  levelStr = "INFO";  break;
            case 2:  levelStr = "WARN";  break;
            case 3: levelStr = "ERROR"; break;
            }
            fprintf(stderr, "[ByteWeaver][%s] %s\n", levelStr, buffer);
        }
    }

    void debug(const char* fmt, ...) {
        va_list args; va_start(args, fmt);
        log_internal(0, fmt, args);
        va_end(args);
    }
    void info(const char* fmt, ...) {
        va_list args; va_start(args, fmt);
        log_internal(1, fmt, args);
        va_end(args);
    }
    void warn(const char* fmt, ...) {
        va_list args; va_start(args, fmt);
        log_internal(2, fmt, args);
        va_end(args);
    }
    void error(const char* fmt, ...) {
        va_list args; va_start(args, fmt);
        log_internal(3, fmt, args);
        va_end(args);
    }

} // namespace byteweaver