#pragma once

#include "LogUtils.h"
#include "RemoteConsole.h"
#include "Logger.h"

namespace LogUtils
{
    std::atomic_bool RemoteConsole::_AutoReconnect = false;
    std::atomic_bool RemoteConsole::_Enabled = false;

    HANDLE RemoteConsole::_Pipe = nullptr;
    const char* RemoteConsole::_PipeName = R"(\\.\pipe\ConsoleLoggerPipe)";

    bool RemoteConsole::Connect()
    {
        const HANDLE pipe = CreateFileA(
            _PipeName,              // Name of the named pipe
            GENERIC_READ | GENERIC_WRITE,  // Access: you want to read and write
            0,                      // No sharing
            nullptr,                // Default security
            OPEN_EXISTING,          // Open the existing pipe don't create it
            0,                      // Default attributes (can be FILE_FLAG_OVERLAPPED if async)
            nullptr);               // No template file


        if (pipe == INVALID_HANDLE_VALUE) {
            Logger::Error("[RCON] Unable to establish connection. Invalid pipe handle!");
            return false;
        }

        _Pipe = pipe;
        _Enabled = true;

        return true;
    }

    bool RemoteConsole::Reconnect()
    {
        {
            if (!_AutoReconnect)
                return false;

            if (_Pipe)
                return true;
        }
        return Connect();
    }

    bool RemoteConsole::IsConnected()
    {
        if (!_Pipe)
            return false;

        DWORD bytesAvailable = 0;
        if (const bool result = PeekNamedPipe(_Pipe, nullptr, 0, nullptr, &bytesAvailable, nullptr); result == FALSE)
        {
            CloseHandle(_Pipe);
            _Pipe = nullptr;
            _Enabled = FALSE;
            _AutoReconnect = FALSE;
            Logger::Error("[RCON] Pipe connection broken, disconnecting!");
            return false;
        }

        return true;
    }

    void RemoteConsole::Disconnect()
    {
        if (_Pipe)
        {
            CloseHandle(_Pipe);
            _Pipe = nullptr;
        }
        _Enabled = false;
        _AutoReconnect = false;
    }

    void RemoteConsole::Write(const std::string& msg)
    {
        if (!_Enabled) {
            Logger::Error("[RCON] Cannot write to console while disabled/disconnected!");
            return;
        }

        if (!_Pipe || _Pipe == INVALID_HANDLE_VALUE) {
            _Enabled = false;
            _AutoReconnect = false;
            Logger::Error("[RCON] Cannot write to invalid pipe! Disconnecting!");
            return;
        }

        DWORD written;

        if (const BOOL success = WriteFile(_Pipe, msg.c_str(), msg.size(), &written, nullptr); !success || written != msg.size())
        {
            _Enabled = false;
            const DWORD err = GetLastError();
            Logger::Error("[RCON] Failed to write to named pipe: %d", err);

            CloseHandle(_Pipe);
            _Pipe = nullptr;
        }
    }

    void RemoteConsole::SetAutoReconnect(const bool enabled)
    {
        _AutoReconnect = enabled;
    }

    void RemoteConsole::SetEnabled(const bool enabled)
    {
        _Enabled = enabled;

        if (!enabled) {
            Logger::Debug("[RCON] Console Logging Disabled!");
            Disconnect(); // safe here, it handles its own locking
            return;
        }
        Logger::Debug("[RCON] Console Logging Enabled!");
    }

    bool RemoteConsole::IsEnabled()
    {
        return _Enabled;
    }
}
