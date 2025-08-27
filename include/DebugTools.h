// Copyright(C) 2025 0xKate - MIT License

#pragma once

#include <dbghelp.h>
#pragma comment(lib, "Dbghelp.lib")
#include <psapi.h>

namespace ByteWeaver {
namespace DebugTools {

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
                debug("[ModuleInfo] - Name         : %s", ModuleName.c_str());
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
        static ModuleInfo GetModuleInfo(std::wstring& moduleName);

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
                if (len < 0) len = (int)strlen(msg); // handle truncation semantics

                if (SymbolLoader::SymLoaded) {
                    DWORD64 displacement = 0;
                    DWORD   displacement32 = 0;

                    // SYMBOL_INFO 
                    char buffer[sizeof(SYMBOL_INFO) + 512]{};
                    auto* symbol = reinterpret_cast<SYMBOL_INFO*>(buffer);
                    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
                    symbol->MaxNameLen = 512;

                    IMAGEHLP_LINE64 line{};
                    line.SizeOfStruct = sizeof(line);

                    std::lock_guard<std::mutex> lock(SymbolLoader::SymMutex);

                    if (SymFromAddr(GetCurrentProcess(),
                        static_cast<DWORD64>(CallAddress),
                        &displacement, symbol))
                    {
                        int n = _snprintf_s(msg + len, sizeof(msg) - len, _TRUNCATE,
                            "  %s+0x%llx",
                            symbol->Name,
                            static_cast<unsigned long long>(displacement));
                        if (n > 0) len += n;
                    }

                    if (SymGetLineFromAddr64(GetCurrentProcess(),
                        static_cast<DWORD64>(CallAddress),
                        &displacement32, &line))
                    {
                        int n = _snprintf_s(msg + len, sizeof(msg) - len, _TRUNCATE,
                            "  [%s:%lu]",
                            line.FileName,
                            static_cast<unsigned long>(line.LineNumber));
                        if (n > 0) len += n;
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
        static TraceInfo Capture(USHORT skip = 1, USHORT maxFrames = 62) {
            if (maxFrames > 62) maxFrames = 62;

            TraceInfo traceback = TraceInfo{};

            traceback.StackSize = RtlCaptureStackBackTrace(skip, maxFrames, traceback.Stack.data(), nullptr);            
            traceback.Frames.reserve(traceback.StackSize);

            for (USHORT i = 0; i < traceback.StackSize; ++i) {
                traceback.Frames.push_back(FrameInfo{
                    reinterpret_cast<uintptr_t>(traceback.Stack[i]),
                    static_cast<USHORT>(i)
                    });
            }
            return traceback;
        }
    };

}}
