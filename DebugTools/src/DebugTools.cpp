// Copyright(C) 2025 0xKate - MIT License

#include <DebugTools.h>
#include <MemoryManager.h>

#include <utility>
#include <psapi.h>

namespace ByteWeaver::DebugTools {
    // ---- SymbolLoader ----
    // Serialize all Sym* calls.
    bool SymbolLoader::InvadeProcess = false;
    bool SymbolLoader::SymLoaded = false;
    std::mutex SymbolLoader::SymMutex;
    std::atomic<int> SymbolLoader::SymRefCount{ 0 };

    std::vector<const char*> SymbolLoader::TargetModules{ "kernel32.dll" };

    // --- Symbol Init/Teardown ---
    // WARNING: Symbols WILL be initialized, and you MUST call CleanupSymbols() if you want to detach gracefully.
    void SymbolLoader::EnsureSymInit()
    {
        // DO NOT call from DllMain.
        static bool ok = InitSymbols();
        (void)ok;
    }

    void SymbolLoader::SetTargetModules(std::vector<const char*> targetModules)
    {
        std::lock_guard lock(SymMutex);
        TargetModules = std::move(targetModules);
    }

    void SymbolLoader::LoadModuleSymbols()
    {
        const HANDLE& hProcess = GetCurrentProcess();
        Debug("[DebugTools] Loading module symbols...");
        for (const auto name : TargetModules) {
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
                Debug("[DebugTools] Failed to load symbols for %s", fullPath);
            }
            else {
                Debug("[DebugTools] Loaded symbols for %s", fullPath);
            }
        }
        Debug("[DebugTools] Finished loading symbols.\n");
    }

    bool SymbolLoader::InitSymbols()
    {
        std::lock_guard lock(SymMutex);
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

    void SymbolLoader::CleanupSymbols()
    {
        std::lock_guard lock(SymMutex);
        if (const int prev = SymRefCount.fetch_sub(1, std::memory_order_acq_rel); prev == 1 && SymLoaded) {
            SymCleanup(GetCurrentProcess());
            SymLoaded = false;
        }
    }

    void SymbolLoader::ForceCleanupSymbols()
    {
        std::lock_guard lock(SymMutex);
        if (SymLoaded) {
            SymRefCount.store(0, std::memory_order_release);
            SymCleanup(GetCurrentProcess());
            SymLoaded = false;
        }
    }

    // ---- Inspection ----
    Inspection::ModuleInfo Inspection::GetModuleInfo(const std::wstring& moduleName)
    {
        if (HMODULE hMod = GetModuleHandleW(moduleName.c_str()))
            return GetModuleInfo(reinterpret_cast<uintptr_t>(hMod));
        return ModuleInfo{};
    }

    Inspection::ModuleInfo Inspection::GetModuleInfo(const uintptr_t address)
    {
        const auto [start, end] = MemoryManager::GetModuleBounds(address);
        const auto fqp = MemoryManager::GetModulePath(address);

        ModuleInfo info{};
        info.ModuleBase = start;
        info.ModuleEnd = end;
        info.ModuleSize = end - start;

        if (!fqp.empty()) {
            info.ModuleName = fqp.filename().native();
            info.ModulePath = fqp;
        }

        info.ModuleValid = true;
        if (start == 0x0 || end == 0x0)
            info.ModuleValid = false;

        return info;
    }

#ifdef _WIN64
    Inspection::FunctionInfo Inspection::GetFunctionInfo(const uintptr_t address)
    {
        const auto modInfo = GetModuleInfo(address);
        auto [start, end] = MemoryManager::GetFunctionBounds(address);

        FunctionInfo info{ modInfo };
        info.FunctionStart = start;
        info.FunctionEnd = end;
        info.FunctionSize = end - start;

        MEMORY_BASIC_INFORMATION mbi;
        if (const size_t result = VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)); result == 0 || result < sizeof(mbi)) {
            Warn("[FunctionInfo] VirtualQuery Failed!");
            info.FunctionValid = false;
        }
        else {
            info.Executable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        }

        if (start == 0x0 || end == 0x0)
            info.FunctionValid = false;

        return info;
    }
#endif

}
