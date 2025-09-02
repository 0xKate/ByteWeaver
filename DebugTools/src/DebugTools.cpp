// Copyright(C) 2025 0xKate - MIT License

#include "ByteWeaver.h"
#include "DebugTools.h"

#include <utility>
#include "MemoryManager.h"


namespace ByteWeaver::DebugTools {
    // ---- SymbolLoader ----
    // Serialize all Sym* calls.
    std::mutex SymbolLoader::SymMutex;
    std::atomic<int> SymbolLoader::SymRefCount{ 0 };
    bool SymbolLoader::SymLoaded = false;
    bool SymbolLoader::InvadeProcess = false;
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
        debug("[DebugTools] Loading module symbols...");
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
            warn("[FunctionInfo] VirtualQuery Failed!");
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

    // ---- ProcessDumper ----
    // -- Implementation --

    void ProcessDumper::AppendRegion(const MEMORY_BASIC_INFORMATION& mbi, ModuleInfoEx::RegionInfo& out) {
    out.Start = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    out.Size  = mbi.RegionSize;
    out.End   = out.Start + out.Size;
    out.AllocationBase = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
    out.State   = mbi.State;
    out.Protect = mbi.Protect;
    out.Type    = mbi.Type;
}

// Try to extract a display path/name for an allocation (works for MEM_IMAGE/MEM_MAPPED)
void ProcessDumper::TryFillPathName(const uintptr_t anyVAInThisAllocation, std::filesystem::path& pathOut, std::wstring& nameOut) {
    wchar_t buf[MAX_PATH] = {};
    if (GetMappedFileNameW(GetCurrentProcess(), const_cast<LPVOID>(reinterpret_cast<LPCVOID>(anyVAInThisAllocation)), buf, MAX_PATH) && buf[0]) {
        pathOut = buf;
        nameOut = pathOut.filename().wstring();
    }
}

// Fill PE-related fields if the allocation looks like a PE mapped at offset 0.
bool ProcessDumper::TryParsePE(ModuleInfoEx& mi) {
    const auto base = mi.ModuleBase;
    if (!base) return false;

    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return false;

    mi.Dos = dos;
    mi.Nt  = nt;
    mi.FileHdr = &nt->FileHeader;
    mi.Opt     = &nt->OptionalHeader;

#ifdef _WIN64
    mi.IsPE32Plus = true;
#else
    mi.IsPE32Plus = mi.Opt->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
#endif

    mi.Characteristics    = mi.FileHdr->Characteristics;
    mi.RelocationsStripped     = (mi.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0;
    mi.IsDLL              = (mi.Characteristics & IMAGE_FILE_DLL) != 0;
    mi.DllCharacteristics = mi.Opt->DllCharacteristics;
    mi.SectionAlignment   = mi.Opt->SectionAlignment;
    mi.FileAlignment      = mi.Opt->FileAlignment;
    mi.SizeOfHeaders      = mi.Opt->SizeOfHeaders;
    mi.TimeDateStamp      = mi.FileHdr->TimeDateStamp;

    mi.ModuleSize = mi.Opt->SizeOfImage;
    mi.ModuleEnd  = mi.ModuleBase + mi.ModuleSize;

    // Sections
    mi.FirstSection = IMAGE_FIRST_SECTION(nt);
    mi.Sections.clear();
    mi.Sections.reserve(mi.FileHdr->NumberOfSections);
    for (WORD i = 0; i < mi.FileHdr->NumberOfSections; ++i) {
        const auto& sh = mi.FirstSection[i];
        ModuleInfoEx::SectionInfo si{};
        std::memcpy(si.Name, sh.Name, 8);
        si.Name[8] = '\0';
        si.Characteristics = sh.Characteristics;
        si.RVA        = sh.VirtualAddress;
        si.VirtualSize= sh.Misc.VirtualSize;
        si.RawPtr     = sh.PointerToRawData;
        si.RawSize    = sh.SizeOfRawData;
        si.VAStart    = mi.ModuleBase + si.RVA;
        si.VAEnd      = si.VAStart + std::max<DWORD>(1, si.VirtualSize);
        mi.Sections.push_back(si);
    }

    // Data directories
    for (size_t i = 0; i < mi.Dirs.size(); ++i) {
        const auto& [virtualAddress, size] = mi.Opt->DataDirectory[i];
        ModuleInfoEx::DirInfo di{};
        di.RVA  = virtualAddress;
        di.Size = size;
        if (i != IMAGE_DIRECTORY_ENTRY_SECURITY) {
            di.VA = di.RVA ? mi.ModuleBase + di.RVA : 0;
        } else {
            di.VA = 0; // file-only
        }
        mi.Dirs[i] = di;
    }
    // Named shortcuts
    auto set = [&](auto& dst, const size_t idx){ dst = mi.Dirs[idx]; };
    set(mi.ExportDir,        IMAGE_DIRECTORY_ENTRY_EXPORT);
    set(mi.ImportDir,        IMAGE_DIRECTORY_ENTRY_IMPORT);
    set(mi.ResourceDir,      IMAGE_DIRECTORY_ENTRY_RESOURCE);
    set(mi.ExceptionDir,     IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    set(mi.SecurityDir,      IMAGE_DIRECTORY_ENTRY_SECURITY);
    set(mi.BaseRelocDir,     IMAGE_DIRECTORY_ENTRY_BASERELOC);
    set(mi.DebugDir,         IMAGE_DIRECTORY_ENTRY_DEBUG);
    set(mi.ArchitectureDir,  IMAGE_DIRECTORY_ENTRY_ARCHITECTURE);
    set(mi.GlobalPtrDir,     IMAGE_DIRECTORY_ENTRY_GLOBALPTR);
    set(mi.TlsDir,           IMAGE_DIRECTORY_ENTRY_TLS);
    set(mi.LoadConfigDir,    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
    set(mi.BoundImportDir,   IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);
    set(mi.IATDir,           IMAGE_DIRECTORY_ENTRY_IAT);
    set(mi.DelayImportDir,   IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
    set(mi.CLRDir,           IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
    set(mi.ReservedDir,      15);

    mi.ModuleValid = true;
    return true;
}

// Walk the whole VA space, group regions by AllocationBase,
// and produce a ModuleInfoEx for every allocation (PE or not).
std::vector<ProcessDumper::ModuleInfoEx> ProcessDumper::EnumerateAllocationsAsModules() {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    auto cur = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    const auto maxAddr = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

    struct Group {
        uintptr_t allocationBase = 0;
        std::vector<ModuleInfoEx::RegionInfo> regions;
        uintptr_t minStart = UINTPTR_MAX;
        uintptr_t maxEnd   = 0;
    };
    std::unordered_map<uintptr_t, Group> groups;
    groups.reserve(1024);

    // 1) Collect all regions
    while (cur < maxAddr) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (const SIZE_T got = VirtualQuery(reinterpret_cast<LPCVOID>(cur), &mbi, sizeof(mbi)); !got) break;

        ModuleInfoEx::RegionInfo ri{};
        AppendRegion(mbi, ri);

        if (ri.AllocationBase) {
            auto& [allocationBase, regions, minStart, maxEnd] = groups[ri.AllocationBase];
            if (allocationBase == 0) allocationBase = ri.AllocationBase;
            regions.push_back(ri);
            minStart = min(minStart, ri.Start);
            maxEnd   = max(maxEnd,   ri.End);
        }

        // Advance
        if (const uintptr_t next = ri.End; next <= cur) { cur += 0x1000; } else { cur = next; } // safety
    }

    // 2) Build ModuleInfoEx list
    std::vector<ModuleInfoEx> out;
    out.reserve(groups.size());

    for (auto& [allocBase, g] : groups) {
        // Sort regions by Start for deterministic output
        std::ranges::sort(g.regions,
                          [](const auto& a, const auto& b){ return a.Start < b.Start; });

        ModuleInfoEx mi{};
        mi.AllocationBase = allocBase;
        mi.ModuleBase     = allocBase;            // assume image at offset 0
        mi.ModuleEnd      = g.maxEnd;
        mi.ModuleSize     = g.maxEnd - allocBase;
        mi.Regions        = std::move(g.regions);

        // Try to get a path/name (works for mapped/image types)
        // Use the first region's address as a probe.
        if (!mi.Regions.empty())
            TryFillPathName(mi.Regions.front().Start, mi.ModulePath, mi.ModuleName);

        // If PE present at allocation base, parse it fully.
        if (TryParsePE(mi)) {
            // If name still empty, try to synthesize from PE export name (optional)
            if (mi.ModuleName.empty()) {
                // nothing fancy here—could be extended by reading export DLL name
            }
        } else {
            // Not a PE: it could be a heap allocation, JIT region, or a manually
            // mapped image not at offset 0. We keep it as a raw mapping.
            mi.ModuleValid = false;
        }

        out.push_back(std::move(mi));
    }

    // Optional: stable order by base address
    std::ranges::sort(out,
                      [](const auto& a, const auto& b){ return a.ModuleBase < b.ModuleBase; });

    return out;
}

// Convenience: find a "module" (allocation group) owning a VA
const ProcessDumper::ModuleInfoEx* ProcessDumper::FindAllocationForVA(const std::vector<ModuleInfoEx>& mods, const uintptr_t va) {
    for (const auto& m : mods) {
        if (va >= m.AllocationBase && va < m.ModuleEnd) return &m;
    }
    return nullptr;
}

}
