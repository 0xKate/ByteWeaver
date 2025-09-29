// Copyright(C) 2025 0xKate - MIT License

#pragma once

#include "ByteWeaverPCH.h"

#include <dbghelp.h>
#pragma comment(lib, "Dbghelp.lib")

namespace ByteWeaver::DebugTools
{
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

            void Dump() const {
                Debug("[ModuleInfo] - Name         : %ws", ModuleName.c_str());
                Debug("[ModuleInfo] - Path         : %s", ModulePath.string().c_str());
                Debug("[ModuleInfo] - Base         : " ADDR_FMT, ModuleBase);
                Debug("[ModuleInfo] - End          : " ADDR_FMT, ModuleEnd);
                Debug("[ModuleInfo] - Size         : %zu bytes", ModuleSize);
                Debug("[ModuleInfo] - IsValid      : %s", ModuleValid ? L"true" : L"false");
            }
        };

        struct FunctionInfo : ModuleInfo {
            uintptr_t FunctionStart = 0x0;
            uintptr_t FunctionEnd = 0x0;
            size_t FunctionSize = 0;
            bool Executable = false;
            bool FunctionValid = false;

            void Dump() const {
                ModuleInfo::Dump();
                Debug("[FunctionInfo] - FuncStart  : " ADDR_FMT, FunctionStart);
                Debug("[FunctionInfo] - FuncEnd    : " ADDR_FMT, FunctionEnd);
                Debug("[FunctionInfo] - FuncSize   : %zu bytes", FunctionSize);
                Debug("[FunctionInfo] - Executable : %s", Executable ? L"true" : L"false");
                Debug("[FunctionInfo] - IsValid    : %s", ModuleValid ? L"true" : L"false");
            }
        };

        static ModuleInfo GetModuleInfo(uintptr_t address);
        static ModuleInfo GetModuleInfo(const std::wstring& moduleName);

#ifdef _WIN64
        static FunctionInfo GetFunctionInfo(uintptr_t address);
#endif
    };

    class Traceback
    {
    public:
        struct FrameInfo {
            uintptr_t CallAddress{};
            USHORT    StackIndex{};
            void Dump() const
            {
                char msg[1024];
                int len = _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                    "[FrameInfo] %-2u) - " ADDR_FMT,
                    StackIndex, CallAddress);
                if (len < 0) len = static_cast<int>(strlen(msg)); // handle truncation semantics

                if (SymbolLoader::SymLoaded) {
                    DWORD64 displacement = 0;
                    DWORD displacement32 = 0;

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
                        // ReSharper disable once CppDFAUnusedValue
                        if (n > 0) len += n;
                    }

                    if constexpr (WIN64) {
                        if (SymGetLineFromAddr64(GetCurrentProcess(), CallAddress, &displacement32, &line)) {
                            _snprintf_s(msg + len, sizeof(msg) - len, _TRUNCATE,
                                "  [%s:%lu]",
                                line.FileName,
                                static_cast<unsigned long>(line.LineNumber));
                        }
                    }
                }

                Debug("%s", msg);
            }

        };

        struct TraceInfo {
            USHORT StackSize{};
            std::array<void*, 62> Stack{};
            std::vector<FrameInfo> Frames{};
            void Dump() const {
                for (FrameInfo frame : Frames) {
                    frame.Dump();
                }
            }
        };


#ifdef _WIN64
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

#else
        static USHORT ScanStackMemory(USHORT skip, USHORT maxFrames, void** addresses) {
            USHORT count = 0;
            DWORD* stackPtr;

            __asm mov stackPtr, esp;

            DWORD* scanStart = stackPtr;
            DWORD* scanEnd = stackPtr + 1024; // Scan up to 4KB of stack

            for (DWORD* ptr = scanStart; ptr < scanEnd && count < maxFrames; ptr++) {
                if (IsBadReadPtr(ptr, 4)) {
                    break;
                }

                if (DWORD addr = *ptr; addr >= 0x00400000 && addr <= 0x7FFFFFFF) {
                    if (!IsBadReadPtr(reinterpret_cast<void*>(addr), 1)) {
                        if (!IsBadReadPtr(reinterpret_cast<void*>(addr - 1), 1)) {
                            if (auto codePtr = reinterpret_cast<BYTE*>(addr - 1); *codePtr == 0xE8 || *codePtr == 0xFF || *codePtr == 0x9A) {
                                if (skip > 0) {
                                    skip--;
                                } else {
                                    addresses[count++] = reinterpret_cast<void*>(addr);
                                }
                            }
                        }
                    }
                }
            }
            return count;
        }

        static TraceInfo Capture(const USHORT skip = 1, USHORT maxFrames = 62) {
            if (maxFrames > 62) maxFrames = 62;

            auto traceback = TraceInfo{};

            traceback.StackSize = ScanStackMemory(skip, maxFrames, traceback.Stack.data());

            traceback.Frames.reserve(traceback.StackSize);
            Debug("Final stacktrace size: %u", traceback.StackSize);

            for (USHORT i = 0; i < traceback.StackSize; ++i) {
                traceback.Frames.push_back(FrameInfo{
                    reinterpret_cast<uintptr_t>(traceback.Stack[i]),
                    i
                });
            }

            return traceback;
        }
#endif
    };
}
