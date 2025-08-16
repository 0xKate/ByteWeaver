// Copyright(C) 2025 0xKate - MIT License

#include "ByteWeaver.h"
#include "DebugTools.h"
#include <dbghelp.h>
#pragma comment(lib, "Dbghelp.lib")
#include <psapi.h>

namespace ByteWeaver {

    // Serialize all Sym* calls.
    std::mutex DebugTools::SymMutex;
    std::atomic<int> DebugTools::SymRefCount{ 0 };
    bool DebugTools::SymLoaded = false;
    std::vector<const char*> DebugTools::TargetModules{ "kernel32.dll" };

    void DebugTools::SetTargetModules(std::vector<const char*> targetModules)
    {
        TargetModules = targetModules;
    }

    // WARNING: Symbols WILL be initalized and you MUST call CleanupSymbols() if you want to detach gracefully.
    void DebugTools::EnsureSymInit()
    {
        // DO NOT call from DllMain.
        static bool ok = InitSymbols();
        (void)ok;
    }

    void DebugTools::LoadModuleSymbols()
    {
        HANDLE hProcess = GetCurrentProcess();

        for (auto name : TargetModules) {
            HMODULE hModule = GetModuleHandleA(name);
            if (!hModule)
                continue;

            MODULEINFO moduleInfo{};
            if (!GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo)))
                continue;

            char fullPath[MAX_PATH] = {};
            if (!GetModuleFileNameA(hModule, fullPath, MAX_PATH))
                continue;

            if (SymLoadModuleEx(hProcess,
                nullptr,                 // hFile
                fullPath,                // Image name (path)
                nullptr,                 // Module name (optional)
                reinterpret_cast<uintptr_t>(hModule),// Base of module
                moduleInfo.SizeOfImage,          // Size of module
                nullptr, 0) == 0)
            {
                debug("Failed to load symbols for %s", fullPath);
            }
            else {
                debug("Loaded symbols for %s", fullPath);
            }
        }
    }

    bool DebugTools::InitSymbols()
    {
        std::lock_guard<std::mutex> lock(SymMutex);
        if (SymRefCount.fetch_add(1) == 0) {
            SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);

            // Add local path + Microsoft symbol server
            //SymSetSearchPath(GetCurrentProcess(),
            //    ".,SRV*c:\\symbols*https://msdl.microsoft.com/download/symbols");

            if (!SymInitialize(GetCurrentProcess(), nullptr, /*fInvadeProcess=*/FALSE)) {
                SymRefCount.fetch_sub(1);
                return false;
            }
            SymLoaded = true;

            LoadModuleSymbols();
        }
        return true;
    }

    void  DebugTools::CleanupSymbols()
    {
        std::lock_guard<std::mutex> lock(SymMutex);
        int prev = SymRefCount.fetch_sub(1, std::memory_order_acq_rel);
        if (prev == 1 && SymLoaded) {
            SymCleanup(GetCurrentProcess());
            SymLoaded = false;
        }
    }

    void  DebugTools::ForceCleanupSymbols()
    {
        std::lock_guard<std::mutex> lock(SymMutex);
        if (SymLoaded) {
            SymRefCount.store(0, std::memory_order_release);
            SymCleanup(GetCurrentProcess());
            SymLoaded = false;
        }
    }

    void DebugTools::PrintAddr(void* stackPointer, const char* prefix)
    {
        EnsureSymInit();

        uintptr_t displacement = 0;
        char buffer[sizeof(SYMBOL_INFO) + 512]{};
        auto* symbol = reinterpret_cast<SYMBOL_INFO*>(buffer);
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = 512;

        IMAGEHLP_LINE64 line{};
        line.SizeOfStruct = sizeof(line);
        DWORD displacement32 = 0;

        uintptr_t address = reinterpret_cast<uintptr_t>(stackPointer);

#if defined(_WIN64)
        const char* ptrFmt = "%s0x%016llx";
#else
        const char* ptrFmt = "%s0x%08x";
#endif

        char msg[1024];
        int len = sprintf_s(msg, sizeof(msg), ptrFmt, prefix ? prefix : "", address);
        {
            std::lock_guard<std::mutex> lock(SymMutex);
            if (SymLoaded && SymFromAddr(GetCurrentProcess(), address, &displacement, symbol)) {
                len += sprintf_s(msg + len, sizeof(msg) - len, "  %s", symbol->Name);
            }
            if (SymLoaded && SymGetLineFromAddr64(GetCurrentProcess(), address, &displacement32, &line)) {
                len += sprintf_s(msg + len, sizeof(msg) - len, "  [%s:%lu]", line.FileName, line.LineNumber);
            }
        }

        debug("%s", msg);
    }

    // WARNING: Symbols WILL be initalized and you MUST call CleanupSymbols() if you want to detach gracefully.
    void DebugTools::PrintStackTrace()
    {
        void* stack[64];
        USHORT frames = CaptureStackBackTrace(0, 64, stack, nullptr);
        for (USHORT i = 0; i < frames; ++i) {
            char prefix[32];
            sprintf_s(prefix, sizeof(prefix), "Frame %-2u: ", i);
            PrintAddr(stack[i], prefix);
        }
    }

}
