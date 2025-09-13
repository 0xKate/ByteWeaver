// Copyright(C) 2025 0xKate - MIT License

#include "ByteWeaver.h"

namespace ByteWeaver {

    static LogFunction LogCallback = nullptr;
    static std::mutex LogMutex;

    void SetLogCallback(const LogFunction fn) {
        LogCallback = fn;
    }

    static void LogInternal(const int level, const char* fmt, const va_list args) {
        char buffer[1024];
        vsnprintf(buffer, sizeof(buffer), fmt, args);

        std::lock_guard lock(LogMutex);
        if (LogCallback) {
            LogCallback(level, buffer);
        }
        else {
            // default fallback
            const char* levelStr = nullptr;
            switch (level) {
            case 0: levelStr = "DEBUG"; break;
            case 1:  levelStr = "INFO";  break;
            case 2:  levelStr = "WARN";  break;
            case 3: levelStr = "ERROR"; break;
            default: ;
            }
            fprintf(stderr, "[ByteWeaver][%s] %s\n", levelStr, buffer);
        }
    }

    void Debug(const char* fmt, ...) {
        va_list args; va_start(args, fmt);
        LogInternal(0, fmt, args);
        va_end(args);
    }
    void Info(const char* fmt, ...) {
        va_list args; va_start(args, fmt);
        LogInternal(1, fmt, args);
        va_end(args);
    }
    void Warn(const char* fmt, ...) {
        va_list args; va_start(args, fmt);
        LogInternal(2, fmt, args);
        va_end(args);
    }
    void Error(const char* fmt, ...) {
        va_list args; va_start(args, fmt);
        LogInternal(3, fmt, args);
        va_end(args);
    }

}