// Copyright(C) 2025 0xKate - MIT License

#include "ByteWeaver.h"
#include "DebugTools.h"
#include "MemoryManager.h"

namespace ByteWeaver {
namespace DebugTools {

    // ---- SymbolLoader ----
    // Serialize all Sym* calls.
    std::mutex SymbolLoader::SymMutex;
    std::atomic<int> SymbolLoader::SymRefCount{ 0 };
    bool SymbolLoader::SymLoaded = false;
    bool SymbolLoader::InvadeProcess = false;
    std::vector<const char*> SymbolLoader::TargetModules{ "kernel32.dll" };

    // --- Symbol Init/Teardown ---
    // WARNING: Symbols WILL be initalized and you MUST call CleanupSymbols() if you want to detach gracefully.
    void SymbolLoader::EnsureSymInit()
    {
        // DO NOT call from DllMain.
        static bool ok = InitSymbols();
        (void)ok;
    }

    void SymbolLoader::SetTargetModules(std::vector<const char*> targetModules)
    {
        std::lock_guard<std::mutex> lock(SymMutex);
        TargetModules = targetModules;
    }

    void SymbolLoader::LoadModuleSymbols()
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

    bool SymbolLoader::InitSymbols()
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

    void SymbolLoader::CleanupSymbols()
    {
        std::lock_guard<std::mutex> lock(SymMutex);
        int prev = SymRefCount.fetch_sub(1, std::memory_order_acq_rel);
        if (prev == 1 && SymLoaded) {
            SymCleanup(GetCurrentProcess());
            SymLoaded = false;
        }
    }

    void SymbolLoader::ForceCleanupSymbols()
    {
        std::lock_guard<std::mutex> lock(SymMutex);
        if (SymLoaded) {
            SymRefCount.store(0, std::memory_order_release);
            SymCleanup(GetCurrentProcess());
            SymLoaded = false;
        }
    }

    // ---- Inspection ----
    Inspection::ModuleInfo Inspection::GetModuleInfo(std::wstring& moduleName)
    {
        HMODULE hMod = GetModuleHandleW(moduleName.c_str());
        if (hMod)
            return GetModuleInfo(reinterpret_cast<uintptr_t>(hMod));
        return ModuleInfo{};
    }

    Inspection::ModuleInfo Inspection::GetModuleInfo(uintptr_t address)
    {
        auto bounds = MemoryManager::GetModuleBounds(address);
        auto fqp = MemoryManager::GetModulePath(address);

        ModuleInfo info{};
        info.ModuleBase = bounds.first;
        info.ModuleEnd = bounds.second;
        info.ModuleSize = bounds.second - bounds.first;

        if (!fqp.empty()) {
            info.ModuleName = fqp.filename().native();
            info.ModulePath = fqp;
        }

        info.ModuleValid = true;
        if (bounds.first == 0x0 || bounds.second == 0x0)
            info.ModuleValid = false;

        return info;
    }

#ifdef _WIN64
    Inspection::FunctionInfo Inspection::GetFunctionInfo(uintptr_t address)
    {
        auto modInfo = GetModuleInfo(address);
        auto bounds = MemoryManager::GetFunctionBounds(address);

        FunctionInfo info{ modInfo };
        info.FunctionStart = bounds.first;
        info.FunctionEnd = bounds.second;
        info.FunctionSize = bounds.second - bounds.first;

        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T result = VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi));
        if (result == 0 || result < sizeof(mbi)) {
            warn("[FunctionInfo] VirtualQuery Failed!");
            info.FunctionValid = false;
        }
        else {
            info.Executable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        }

        if (bounds.first == 0x0 || bounds.second == 0x0)
            info.FunctionValid = false;

        return info;
    }
#endif

}}
