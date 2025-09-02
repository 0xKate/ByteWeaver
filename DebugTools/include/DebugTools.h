// Copyright(C) 2025 0xKate - MIT License

#pragma once

#include <dbghelp.h>
#pragma comment(lib, "Dbghelp.lib")
#include <psapi.h>


namespace ByteWeaver::DebugTools {

	class SymbolLoader {       
	public:
        // --- Symbol Init/Teardown ---
        static bool InvadeProcess;
        static bool SymLoaded;
        static std::mutex SymMutex;
        static void SetTargetModules(std::vector<const char*> targetModules);
        static void LoadModuleSymbols();
        static void EnsureSymInit();
		static void ForceCleanupSymbols();
		static void CleanupSymbols();

	private:
		// Serialize all Sym* calls.		
		static std::atomic<int> SymRefCount;		
		static std::vector<const char*> TargetModules;
		static bool InitSymbols();		
	};

	class Inspection {
	public:
        struct ModuleInfo {
            std::wstring ModuleName{};
            std::filesystem::path ModulePath{};
            uintptr_t ModuleBase = 0x0;
            uintptr_t ModuleEnd = 0x0;
            size_t ModuleSize = 0;
            bool ModuleValid = false;

            void dump() const {
                debug("[ModuleInfo] - Name         : %ws", ModuleName.c_str());
                debug("[ModuleInfo] - Path         : %s", ModulePath.string().c_str());
                debug("[ModuleInfo] - Base         : " ADDR_FMT, ModuleBase);
                debug("[ModuleInfo] - End          : " ADDR_FMT, ModuleEnd);
                debug("[ModuleInfo] - Size         : %zu bytes", ModuleSize);
                debug("[ModuleInfo] - IsValid      : %s", ModuleValid ? L"true" : L"false");
            }
        };

        struct FunctionInfo : ModuleInfo {
            uintptr_t FunctionStart = 0x0;
            uintptr_t FunctionEnd = 0x0;
            size_t FunctionSize = 0;
            bool Executable = false;
            bool FunctionValid = false;

            void dump() const {
                ModuleInfo::dump();
                debug("[FunctionInfo] - FuncStart  : " ADDR_FMT, FunctionStart);
                debug("[FunctionInfo] - FuncEnd    : " ADDR_FMT, FunctionEnd);
                debug("[FunctionInfo] - FuncSize   : %zu bytes", FunctionSize);
                debug("[FunctionInfo] - Executable : %s", Executable ? L"true" : L"false");
                debug("[FunctionInfo] - IsValid    : %s", ModuleValid ? L"true" : L"false");
            }
        };

        static ModuleInfo GetModuleInfo(uintptr_t address);
        static ModuleInfo GetModuleInfo(const std::wstring& moduleName);

        #ifdef _WIN64
		static FunctionInfo GetFunctionInfo(uintptr_t address);
        #endif
	};

    class Traceback {
    public:
        struct FrameInfo {
            uintptr_t CallAddress{};
            USHORT    StackIndex{};
            void dump() const
            {
                char msg[1024];
                int len = _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                    "[FrameInfo] %-2u) - " ADDR_FMT,
                    StackIndex, CallAddress);
                if (len < 0) len = static_cast<int>(strlen(msg)); // handle truncation semantics

                if (SymbolLoader::SymLoaded) {
                    DWORD64 displacement = 0;
                    DWORD   displacement32 = 0;

                    // SYMBOL_INFO 
                    // ReSharper disable once CppLocalVariableMayBeConst
                    char buffer[sizeof(SYMBOL_INFO) + 512]{};
                    auto* symbol = reinterpret_cast<SYMBOL_INFO*>(buffer);
                    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
                    symbol->MaxNameLen = 512;

                    IMAGEHLP_LINE64 line{};
                    line.SizeOfStruct = sizeof(line);

                    std::lock_guard lock(SymbolLoader::SymMutex);

                    if (SymFromAddr(GetCurrentProcess(), CallAddress, &displacement, symbol)) {
                        const int n = _snprintf_s(msg + len, sizeof(msg) - len, _TRUNCATE,
                            "  %s+0x%llx",
                            symbol->Name,
                            static_cast<unsigned long long>(displacement));
                        if (n > 0) len += n;
                    }

                    if (SymGetLineFromAddr64(GetCurrentProcess(), CallAddress, &displacement32, &line)) {
                        _snprintf_s(msg + len, sizeof(msg) - len, _TRUNCATE,
                            "  [%s:%lu]",
                            line.FileName,
                            static_cast<unsigned long>(line.LineNumber));
                    }
                }

                debug("%s", msg);
            }

        };

        struct TraceInfo {
            USHORT StackSize{};
            std::array<void*, 62> Stack{};
            std::vector<FrameInfo> Frames{};
            void dump() const {
                for (FrameInfo frame : Frames) {
                    frame.dump();
                }
            }
        };

        // skip: frames to skip from the top (this function, its caller, etc.)
        // maxFrames: how many frames to capture (capped at 62 by the API)
        static TraceInfo Capture(const USHORT skip = 1, USHORT maxFrames = 62) {
            if (maxFrames > 62) maxFrames = 62;

            auto traceback = TraceInfo{};

            traceback.StackSize = RtlCaptureStackBackTrace(skip, maxFrames, traceback.Stack.data(), nullptr);            
            traceback.Frames.reserve(traceback.StackSize);

            for (USHORT i = 0; i < traceback.StackSize; ++i) {
                traceback.Frames.push_back(FrameInfo{
                    reinterpret_cast<uintptr_t>(traceback.Stack[i]),
                    i
                    });
            }
            return traceback;
        }
    };

    class ProcessDumper {
    public:
        struct ModuleInfoEx : Inspection::ModuleInfo {
            // --- VirtualQuery region granularity ---
            struct RegionInfo {
                uintptr_t Start = 0;         // BaseAddress
                size_t    Size  = 0;         // RegionSize
                uintptr_t End   = 0;         // Start + Size
                uintptr_t AllocationBase = 0;
                DWORD State   = 0;           // MEM_COMMIT / MEM_RESERVE / MEM_FREE
                DWORD Protect = 0;           // PAGE_*
                DWORD Type    = 0;           // MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE

                [[nodiscard]] bool Readable() const {
                    if (State != MEM_COMMIT) return false;
                    return (Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0;
                }
            };

            // Aggregated regions for this allocation
            std::vector<RegionInfo> Regions;
            uintptr_t               AllocationBase = 0; // same as ModuleBase if PE at offset 0

            // PEs: headers & section map (if recognized)
            PIMAGE_DOS_HEADER       Dos = nullptr;
            PIMAGE_NT_HEADERS       Nt  = nullptr;
            PIMAGE_FILE_HEADER      FileHdr = nullptr;
            PIMAGE_OPTIONAL_HEADER  Opt = nullptr;
            PIMAGE_SECTION_HEADER   FirstSection = nullptr;

            bool      IsPE32Plus = false;
            bool      IsDLL      = false;
            bool      RelocationsStripped = false;

            DWORD     Characteristics = 0;
            WORD      DllCharacteristics = 0;
            DWORD     SectionAlignment = 0;
            DWORD     FileAlignment    = 0;
            size_t    SizeOfHeaders    = 0;
            DWORD     TimeDateStamp    = 0;

            struct SectionInfo {
                char      Name[9]{};
                DWORD     Characteristics = 0;
                DWORD     RVA = 0;
                DWORD     VirtualSize = 0;
                DWORD     RawPtr = 0;
                DWORD     RawSize = 0;
                uintptr_t VAStart = 0;
                uintptr_t VAEnd   = 0;
                [[nodiscard]] bool ContainsRva(DWORD rva) const {
                    return rva >= RVA && rva < (RVA + std::max<DWORD>(1, VirtualSize));
                }
                [[nodiscard]] bool ContainsVa(uintptr_t va) const {
                    return va >= VAStart && va < VAEnd;
                }
            };
            std::vector<SectionInfo> Sections;

            struct DirInfo {
                DWORD     RVA = 0;
                DWORD     Size = 0;
                uintptr_t VA = 0; // 0 for Security (file-only)
                [[nodiscard]] bool Present() const { return RVA && Size; }
            };
            std::array<DirInfo, IMAGE_NUMBEROF_DIRECTORY_ENTRIES> Dirs{};
            DirInfo ExportDir, ImportDir, ResourceDir, ExceptionDir, SecurityDir, BaseRelocDir,
                    DebugDir, ArchitectureDir, GlobalPtrDir, TlsDir, LoadConfigDir, BoundImportDir,
                    IATDir, DelayImportDir, CLRDir, ReservedDir;

            // RVA/VA helpers (valid only if ModuleBase set)
            [[nodiscard]] uintptr_t RVAtoVA(const DWORD rva) const { return rva ? (ModuleBase + rva) : 0; }
            [[nodiscard]] DWORD     VAtoRVA(const uintptr_t va) const { return (va >= ModuleBase && va < ModuleEnd) ? static_cast<DWORD>(va - ModuleBase) : 0; }

            [[nodiscard]] DWORD RVAtoFileOffset(const DWORD rva) const {
                for (const auto& s : Sections) {
                    if (s.ContainsRva(rva)) {
                        const DWORD delta = rva - s.RVA;
                        if (delta >= s.RawSize) return 0;
                        return s.RawPtr + delta;
                    }
                }
                return 0;
            }
        };

        static std::vector<ModuleInfoEx> EnumerateAllocationsAsModules();
        static const ModuleInfoEx* FindAllocationForVA(const std::vector<ModuleInfoEx>& mods, uintptr_t va);

    private:
        static void AppendRegion(const MEMORY_BASIC_INFORMATION& mbi, ModuleInfoEx::RegionInfo& out);
        static void TryFillPathName(uintptr_t anyVAInThisAllocation, std::filesystem::path& pathOut,
                                    std::wstring& nameOut);
        static bool TryParsePE(ModuleInfoEx& mi);
    };
}
