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
    bool DebugTools::InvadeProcess = false;
    std::vector<const char*> DebugTools::TargetModules{ "kernel32.dll" };

    // --- Symbol Init/Teardown ---
    // WARNING: Symbols WILL be initalized and you MUST call CleanupSymbols() if you want to detach gracefully.
    void DebugTools::EnsureSymInit()
    {
        // DO NOT call from DllMain.
        static bool ok = InitSymbols();
        (void)ok;
    }

    void DebugTools::SetTargetModules(std::vector<const char*> targetModules)
    {
        TargetModules = targetModules;
    }

    void DebugTools::LoadModuleSymbols()
    {
        HANDLE hProcess = GetCurrentProcess();
        debug("[DebugTools] Loading module symbols...");
        for (auto name : TargetModules) {
            HMODULE hModule = GetModuleHandleA(name);
            if (!hModule)
                continue;

            MODULEINFO moduleInfo{};
            if (!K32GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo)))
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
                debug("[DebugTools] Failed to load symbols for %s", fullPath);
            }
            else {
                debug("[DebugTools] Loaded symbols for %s", fullPath);
            }
        }
        debug("[DebugTools] Finished loading symbols.\n");
    }

    bool DebugTools::InitSymbols()
    {
        std::lock_guard<std::mutex> lock(SymMutex);
        if (SymRefCount.fetch_add(1) == 0) {
            SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);

            // Add local path + Microsoft symbol server
            //SymSetSearchPath(GetCurrentProcess(),
            //    ".,SRV*c:\\symbols*https://msdl.microsoft.com/download/symbols");

            if (!SymInitialize(GetCurrentProcess(), nullptr, /*fInvadeProcess=*/InvadeProcess)) {
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
}
