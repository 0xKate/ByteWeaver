#pragma once

#include "LogUtils.h"
#include "Logger.h"
#include "RemoteConsole.h"

//#define LOGGER_ENABLE_TIMESTAMP
//#define LOGGER_ENABLE_THREAD_DEBUG

namespace LogUtils
{
    std::filesystem::path LogLocation;
    LogLevel Logger::_LogLevel = LogLevel::LOG_INFO;
    std::ofstream Logger::_FileStream;
    std::mutex Logger::_Mutex;

    void Logger::Initialize(const std::filesystem::path& logPath, const LogLevel level) {
        std::lock_guard lock(_Mutex);
        LogLocation = logPath;
        _LogLevel = level;
        _FileStream.open(logPath, std::ios::app);
        if (!_FileStream.is_open()) {
            throw std::runtime_error("Unable to open log file.");
        }
    }

    void Logger::SetLogLevel(const LogLevel level) {
        std::lock_guard lock(_Mutex);
        _LogLevel = level;
    }

    void Logger::Debug(const char* format, ...) {
        std::lock_guard lock(_Mutex);
        va_list args;
        va_start(args, format);
        const std::string message = FormatArgs(format, args);
        va_end(args);
        Log(LogLevel::LOG_DEBUG, message);
    }

    void Logger::Info(const char* format, ...) {
        std::lock_guard lock(_Mutex);
        va_list args;
        va_start(args, format);
        const std::string message = FormatArgs(format, args);
        va_end(args);
        Log(LogLevel::LOG_INFO, message);
    }

    void Logger::Warn(const char* format, ...) {
        std::lock_guard lock(_Mutex);
        va_list args;
        va_start(args, format);
        const std::string message = FormatArgs(format, args);
        va_end(args);
        Log(LogLevel::LOG_WARN, message);
    }

    void Logger::Error(const char* format, ...) {
        std::lock_guard lock(_Mutex);
        va_list args;
        va_start(args, format);
        const std::string message = FormatArgs(format, args);
        va_end(args);
        Log(LogLevel::LOG_ERROR, message);
    }

    std::string Logger::FormatArgs(const char* format, const va_list args) {
        char buffer[8096];
        vsnprintf(buffer, sizeof(buffer), format, args);
        return std::string(buffer);
    }

    void Logger::Log(const std::string& message)
    {
        std::lock_guard lock(_Mutex);

        if (RemoteConsole::IsEnabled())
            RemoteConsole::Write(message + "\n");

        if (_FileStream.is_open()) {
            _FileStream << message << std::endl;
        }
        std::cout << message << std::endl;
    }

    void Logger::Log(const LogLevel level, const std::string& message) {
        auto msg = FormatLogMessage(level, message);

    #ifdef LOGGER_ENABLE_THREAD_DEBUG
        std::ostringstream oss;
        oss << "[" << std::this_thread::get_id() << "]";
        std::string threadIdStr = oss.str();

        msg.insert(0, threadIdStr);
    #endif

    #ifdef LOGGER_ENABLE_TIMESTAMP
        // Get the current time
        auto now = std::chrono::system_clock::now();
        auto now_time = std::chrono::system_clock::to_time_t(now);

        // Convert to a human-readable format
        std::tm tm_buffer;

    #ifdef _WIN32
        // Windows uses localtime_s
        localtime_s(&tm_buffer, &now_time);
    #else
        // POSIX (Linux, Mac) uses localtime_r
        localtime_r(&now_time, &tm_buffer);
    #endif

        // Format the timestamp with milliseconds
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
        std::ostringstream timestampStream;
        timestampStream << std::put_time(&tm_buffer, "[%Y-%m-%d %H:%M:%S") << "."
            << std::setw(3) << std::setfill('0') << ms.count() << "]";

        std::string timestampStr = timestampStream.str();

        // Insert the timestamp into the message
        msg.insert(0, timestampStr);
    #endif

        if (_FileStream.is_open()) {
            _FileStream << msg << std::endl;
        }

        if (RemoteConsole::IsEnabled())
        {
            if (_LogLevel <= level) {
                RemoteConsole::Write(msg + "\n");
            }
        }
        else
        {
            if (_LogLevel <= level) {
                if (level > LogLevel::LOG_INFO) {
                        std::cerr << msg << std::endl;
                }
                else {
                        std::cout << msg << std::endl;
                }
            }
        }
    }

    std::string Logger::FormatLogMessage(const LogLevel level, const std::string& message) {
        std::string levelStr;
        switch (level) {
        case LogLevel::LOG_DEBUG: levelStr = "DEBUG"; break;
        case LogLevel::LOG_INFO:  levelStr = "INFO"; break;
        case LogLevel::LOG_WARN:  levelStr = "WARN"; break;
        case LogLevel::LOG_ERROR: levelStr = "ERROR"; break;
        }
        return "[" + levelStr + "]" + message;
    }
}
