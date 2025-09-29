#pragma once

namespace LogUtils
{

#if defined(HAVE_BYTEWEAVER)
    using LogLevel   = ByteWeaver::LogLevel;
    using LogFunction = void(*)(LogLevel, const std::string&);

#elif defined(HAVE_LOGUTILS)
    using LogLevel   = LogUtils::LogLevel;
    using LogFunction = void(*)(LogLevel, const std::string&);

#else
    enum class LogLevel : int {
        LOG_DEBUG,
        LOG_INFO,
        LOG_WARN,
        LOG_ERROR
    };
    using LogFunction = void(*)(LogLevel, const std::string&);
#define HAVE_LOGUTILS
#endif

    class Logger {
    public:
        static void Initialize(const std::filesystem::path& logPath, LogLevel level);
        static void SetLogLevel(LogLevel level);
        static void Debug(const char* format, ...);
        static void Info(const char* format, ...);
        static void Warn(const char* format, ...);
        static void Error(const char* format, ...);
        static void Log(const std::string& message);
        static void Log(LogLevel level, const std::string& message);


    private:
        static LogLevel _LogLevel;
        static std::ofstream _FileStream;
        static std::mutex _Mutex;
        static std::string FormatArgs(const char* format, va_list args);
        static std::string FormatLogMessage(LogLevel level, const std::string& message);
    };
}