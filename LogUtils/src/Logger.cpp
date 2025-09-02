#pragma once

#include "Shared.h"
#include "Logger.h"
#include "RemoteConsole.h"

//#define LOGGER_ENABLE_TIMESTAMP
//#define LOGGER_ENABLE_THREAD_DEBUG

std::filesystem::path logLocation;
LogLevel Logger::logLevel = LogLevel::LOG_INFO;
std::ofstream Logger::fileStream;
std::mutex Logger::mutex;

void Logger::Initialize(std::filesystem::path log_path, LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex);
    logLocation = log_path;
    logLevel = level;
    fileStream.open(log_path, std::ios::app);
    if (!fileStream.is_open()) {
        throw std::runtime_error("Unable to open log file.");
    }
}

void Logger::setLogLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex);
    logLevel = level;
}

void Logger::debug(const char* format, ...) {
    std::lock_guard<std::mutex> lock(mutex);
    va_list args;
    va_start(args, format);
    std::string message = formatArgs(format, args);
    va_end(args);
    log(LogLevel::LOG_DEBUG, message);
}

void Logger::info(const char* format, ...) {
    std::lock_guard<std::mutex> lock(mutex);
    va_list args;
    va_start(args, format);
    std::string message = formatArgs(format, args);
    va_end(args);
    log(LogLevel::LOG_INFO, message);
}

void Logger::warn(const char* format, ...) {
    std::lock_guard<std::mutex> lock(mutex);
    va_list args;
    va_start(args, format);
    std::string message = formatArgs(format, args);
    va_end(args);
    log(LogLevel::LOG_WARN, message);
}

void Logger::error(const char* format, ...) {
    std::lock_guard<std::mutex> lock(mutex);
    va_list args;
    va_start(args, format);
    std::string message = formatArgs(format, args);
    va_end(args);
    log(LogLevel::LOG_ERROR, message);
}

std::string Logger::formatArgs(const char* format, va_list args) {
    char buffer[8096];
    vsnprintf(buffer, sizeof(buffer), format, args);
    return std::string(buffer);
}

void Logger::log(const std::string& message)
{
    std::lock_guard<std::mutex> lock(mutex);

    if (RemoteConsole::IsEnabled())
        RemoteConsole::Write(message + "\n");

    if (fileStream.is_open()) {
        fileStream << message << std::endl;
    }
    std::cout << message << std::endl;
}

void Logger::log(LogLevel level, const std::string& message) {
    auto msg = formatLogMessage(level, message);

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

    if (fileStream.is_open()) {
        fileStream << msg << std::endl;
    }

    if (RemoteConsole::IsEnabled())
    {
        if (logLevel <= level) {
            RemoteConsole::Write(msg + "\n");
        }
    }
    else
    {
        if (logLevel <= level) {
            if (level > LogLevel::LOG_INFO) {
                    std::cerr << msg << std::endl;
            }
            else {
                    std::cout << msg << std::endl;
            }
        }
    }
}

std::string Logger::formatLogMessage(LogLevel level, const std::string& message) {
    std::string levelStr;
    switch (level) {
    case LogLevel::LOG_DEBUG: levelStr = "DEBUG"; break;
    case LogLevel::LOG_INFO:  levelStr = "INFO"; break;
    case LogLevel::LOG_WARN:  levelStr = "WARN"; break;
    case LogLevel::LOG_ERROR: levelStr = "ERROR"; break;
    }
    return "[" + levelStr + "]" + message;
}