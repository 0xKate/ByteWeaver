#pragma once

enum class LogLevel {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
};

class Logger {
public:
    static void Initialize(std::filesystem::path log_path, LogLevel level);
    static void setLogLevel(LogLevel level);
    static void debug(const char* format, ...);
    static void info(const char* format, ...);
    static void warn(const char* format, ...);
    static void error(const char* format, ...);
    static void log(const std::string& message);
    static void log(LogLevel level, const std::string& message);


private:
    static LogLevel logLevel;
    static std::ofstream fileStream;
    static std::mutex mutex;
    static std::string formatArgs(const char* format, va_list args);
    static std::string formatLogMessage(LogLevel level, const std::string& message);
};