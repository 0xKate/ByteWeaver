#include <Windows.h>
#include <iostream>

constexpr auto PIPE_NAME = R"(\\.\pipe\ConsoleLoggerPipe)";

[[noreturn]] void RunLogger()
{
    while (true)
    {
        const HANDLE hPipe = CreateNamedPipeA(
            PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,              // Max instances
            4096, 4096,     // Buffers
            0,
            nullptr);

        if (hPipe == INVALID_HANDLE_VALUE)
        {
            std::cerr << "Failed to create named pipe. Error: " << GetLastError() << "\n";
            Sleep(1000); // Wait before retrying
            continue;
        }

        std::cout << "[Logger] Waiting for client connection...\n";

        if (!ConnectNamedPipe(hPipe, nullptr) && GetLastError() != ERROR_PIPE_CONNECTED)
        {
            std::cerr << "Failed to connect named pipe. Error: " << GetLastError() << "\n";
            CloseHandle(hPipe);
            continue;
        }

        std::cout << "[Logger] Client connected!\n";

        // Block this thread for this pipe instance
        char buffer[512];
        DWORD bytesRead;
        while (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr))
        {
            buffer[bytesRead] = '\0';
            std::cout << buffer << std::flush;
        }

        std::cout << "[Logger] Client disconnected.\n";
        CloseHandle(hPipe);

        // Now loop and create new pipe
    }
}


int main()
{
    RunLogger();
}