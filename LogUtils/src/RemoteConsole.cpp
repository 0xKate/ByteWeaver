#pragma once

#include "Shared.h"
#include "RemoteConsole.h"
#include "Logger.h"

std::atomic_bool RemoteConsole::AutoReconnect = false;
std::atomic_bool RemoteConsole::Enabled = false;

HANDLE RemoteConsole::Pipe = nullptr;
const char* RemoteConsole::PipeName = R"(\\.\pipe\ConsoleLoggerPipe)";

bool RemoteConsole::Connect()
{
    HANDLE pipe = CreateFileA(
        PipeName,              // Name of the named pipe
        GENERIC_READ | GENERIC_WRITE,  // Access: you want to read and write
        0,                      // No sharing
        nullptr,                // Default security
        OPEN_EXISTING,          // Open the existing pipe don't create it
        0,                      // Default attributes (can be FILE_FLAG_OVERLAPPED if async)
        nullptr);               // No template file


    if (pipe == INVALID_HANDLE_VALUE) {
        Logger::error("[RCON] Unable to establish connection. Invalid pipe handle!");
        return false;
    }        

    Pipe = pipe;
    Enabled = true;

    return true;
}

bool RemoteConsole::Reconnect()
{
    {
        if (!AutoReconnect)
            return false;

        if (Pipe)
            return true;
    }
    return Connect();
}

bool RemoteConsole::IsConnected()
{
    if (!Pipe)
        return false;

    DWORD bytesAvailable = 0;
    BOOL result = PeekNamedPipe(Pipe, nullptr, 0, nullptr, &bytesAvailable, nullptr);
    if (result == FALSE)
    {
        CloseHandle(Pipe);
        Pipe = nullptr;
        Enabled = FALSE;
        AutoReconnect = FALSE;
        Logger::error("[RCON] Pipe connection broken, disconnecting!");
        return false;
    }

    return true;
}

void RemoteConsole::Disconnect(bool disableReconnect)
{
    if (Pipe)
    {
        CloseHandle(Pipe);
        Pipe = nullptr;
    }
    Enabled = false;
    AutoReconnect = false;
}

void RemoteConsole::Write(const std::string& msg)
{
    if (!Enabled) {
        Logger::error("[RCON] Cannot write to console while disabled/disconnected!");
        return;
    }

    if (!Pipe || Pipe == INVALID_HANDLE_VALUE) {
        Enabled = false;
        AutoReconnect = false;
        Logger::error("[RCON] Cannot write to invalid pipe! Disconnecting!");
        return;
    }

    DWORD written;
    BOOL success;
    success = WriteFile(Pipe, msg.c_str(), (DWORD)msg.size(), &written, nullptr);

    if (!success || written != msg.size())
    {
        Enabled = false;
        DWORD err = GetLastError();
        Logger::error("[RCON] Failed to write to named pipe: %d", err);

        CloseHandle(Pipe);
        Pipe = nullptr;
    }
}

void RemoteConsole::SetAutoReconnect(bool enabled)
{
    AutoReconnect = enabled;
}

void RemoteConsole::SetEnabled(bool enabled)
{
    Enabled = enabled;

    if (!enabled) {
        Logger::debug("[RCON] Console Logging Disabled!");
        Disconnect(true); // safe here, it handles its own locking
        return;
    }
    Logger::debug("[RCON] Console Logging Enabled!");
}

bool RemoteConsole::IsEnabled()
{
    return Enabled;
}

