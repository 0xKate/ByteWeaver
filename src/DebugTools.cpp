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

    void DebugTools::PrintAddr(void* stackPointer, const char* prefix)
    {
        EnsureSymInit();

        DWORD64 displacement = 0;  // SymFromAddr requires this type
        char buffer[sizeof(SYMBOL_INFO) + 512]{};
        auto* symbol = reinterpret_cast<SYMBOL_INFO*>(buffer);
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = 512;

        IMAGEHLP_LINE64 line{};
        line.SizeOfStruct = sizeof(line);
        DWORD displacement32 = 0;

        // Normalize the pointer to an integer we can print consistently
        const unsigned long long addrULL =
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(stackPointer));
        const int nibbles = static_cast<int>(sizeof(void*) * 2);

        char msg[1025];
        int len = sprintf_s(msg, sizeof(msg), "%s0x%0*llx",
            (prefix ? prefix : ""), nibbles, addrULL);

        {
            std::lock_guard<std::mutex> lock(SymMutex);
            if (SymLoaded && SymFromAddr(GetCurrentProcess(),
                static_cast<DWORD64>(addrULL),
                &displacement, symbol)) {
                len += sprintf_s(msg + len, sizeof(msg) - len, "  %s", symbol->Name);
            }

            if (SymLoaded && SymGetLineFromAddr64(GetCurrentProcess(),
                static_cast<DWORD64>(addrULL),
                &displacement32, &line)) {
                len += sprintf_s(msg + len, sizeof(msg) - len,
                    "  [%s:%lu]", line.FileName, line.LineNumber);
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

    DebugTools::ReturnAddressInfo DebugTools::ResolveReturnAddress(const void* addr) {
        ReturnAddressInfo info{};
        info.returnAddress = const_cast<void*>(addr);
        if (!addr) return info;

        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(addr, &mbi, sizeof(mbi))) return info;

        HMODULE hmod = reinterpret_cast<HMODULE>(mbi.AllocationBase);
        if (!hmod) return info;

        info.moduleHandle = hmod;
        info.moduleBase = reinterpret_cast<uintptr_t>(hmod);
        info.offset = reinterpret_cast<uintptr_t>(addr) - info.moduleBase;

        // get name and path data
        char path[MAX_PATH]{};
        if (GetModuleFileNameA(hmod, path, MAX_PATH)) {
            info.modulePath = path;
            info.moduleName = strrchr(path, '\\') ? strrchr(path, '\\') + 1 : path;
        }

        // Verify it looks like a mapped PE image and extract section
        auto base = reinterpret_cast<const BYTE*>(hmod);

        // DOS header
        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            // NT headers
            auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                base + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                info.isImageMapped = true;

                // Locate section by RVA
                DWORD rva = static_cast<DWORD>(info.offset);
#ifdef _WIN64
                const auto* nth = reinterpret_cast<const IMAGE_NT_HEADERS64*>(nt);
                const IMAGE_FILE_HEADER& fh = nth->FileHeader;
                const IMAGE_SECTION_HEADER* sec =
                    IMAGE_FIRST_SECTION(nt);
#else
                const auto* nth = reinterpret_cast<const IMAGE_NT_HEADERS32*>(nt);
                const IMAGE_FILE_HEADER& fh = nth->FileHeader;
                const IMAGE_SECTION_HEADER* sec =
                    IMAGE_FIRST_SECTION(nt);
#endif
                WORD nsec = fh.NumberOfSections;
                for (WORD i = 0; i < nsec; ++i) {
                    DWORD start = sec[i].VirtualAddress;
                    DWORD size = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize
                        : sec[i].SizeOfRawData;
                    if (rva >= start && rva < start + size) {
                        // Copy section name (8 bytes, not guaranteed null-terminated)
                        size_t len = 0;
                        while (len < 8 && sec[i].Name[len] != '\0') ++len;
                        memcpy(info.section, sec[i].Name, len);
                        info.section[len] = '\0';
                        break;
                    }
                }
            }
        }

        info.valid = true;
        return info;
    }



}
