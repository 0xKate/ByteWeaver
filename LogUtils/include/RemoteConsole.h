#pragma once

namespace LogUtils
{
    class RemoteConsole
    {
        static std::atomic_bool _AutoReconnect;
        static std::atomic_bool _Enabled;
        static HANDLE _Pipe;
        static const char* _PipeName;
    public:
        static bool Connect();
        static bool Reconnect();
        static bool IsConnected();
        static void Disconnect();
        static void Write(const std::string& msg);
        static void SetAutoReconnect(bool enabled = true);
        static void SetEnabled(bool enabled = true);
        static bool IsEnabled();
    };
}



// Add list of commands and callbacks, move command reader code here

/*

std::thread g_CommandReaderThread;
std::atomic_bool g_ShouldStopCommandReader = false;

void HandleCommand(const std::string& cmd)
{
    if (cmd == "unload")
    {
        RemoteConsole::Write("[DLL] Unloading...\n");
        // Trigger your graceful shutdown
    }
    else if (cmd == "ping")
    {
        RemoteConsole::Write("[DLL] Pong!\n");
    }
    else
    {
        RemoteConsole::Write("[DLL] Unknown command: " + cmd + "\n");
    }
}

void StartCommandReader()
{
    g_ShouldStopCommandReader = false;

    g_CommandReaderThread = std::thread([] {
        char buffer[512];
        DWORD bytesRead;

        while (!g_ShouldStopCommandReader && RemoteConsole::Pipe &&
            ReadFile(RemoteConsole::Pipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr))
        {
            if (bytesRead > 0)
            {
                buffer[bytesRead] = '\0';
                std::string command(buffer);
                HandleCommand(command);
            }
        }
        });

    g_CommandReaderThread.detach(); // or store it and join later
}

*/