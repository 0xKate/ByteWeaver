// Copyright(C) 2025 0xKate - MIT License

#include <ByteWeaver.h>
#include <WinDetour.h>
#include <detours.h>

namespace ByteWeaver
{
    Detour::Detour(const uintptr_t targetAddress, PVOID* originalFunction, const PVOID detourFunction)
    {
        this->TargetAddress = targetAddress;
        this->IsPatched = false;
        this->OriginalFunction = originalFunction;
        this->DetourFunction = detourFunction;
        this->IsEnabled = false;

        if constexpr (WIN64) {
            this->OriginalBytes.resize(14);
            memcpy(this->OriginalBytes.data(), reinterpret_cast<void*>(targetAddress), 14);
        }
        else {
            this->OriginalBytes.resize(5);
            memcpy(this->OriginalBytes.data(), reinterpret_cast<void*>(targetAddress), 5);
        }
    }

    bool Detour::Apply()
    {
        if (IsPatched)
            return true;

        __try
        {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(OriginalFunction, DetourFunction);

            PVOID* failedPointer = nullptr;
            if (const LONG result = DetourTransactionCommitEx(&failedPointer); result == NO_ERROR) {
                if constexpr (ENABLE_DETOUR_LOGGING)
                    Debug("[Detour] (Apply) [Target: " ADDR_FMT " -> Detour: " ADDR_FMT "]", reinterpret_cast<void*>(TargetAddress), DetourFunction);
                IsPatched = true;

                if constexpr (WIN64)
                    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(TargetAddress), 14);
                else
                    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(TargetAddress), 5);

                return true;
            }
            const char* failMsg = failedPointer ? static_cast<const char*>(*failedPointer) : "Unknown";
            Error("[Detour] Failed to apply! : %s", failMsg);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            const DWORD code = GetExceptionCode();
            Error("[Detour] Exception occurred during Apply. Code: 0x%08X", code);
        }
        DetourTransactionAbort();
        return false;
    }

    bool Detour::Restore()
    {
        if (!IsPatched)
            return true;

        __try
        {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourDetach(OriginalFunction, DetourFunction);

            PVOID* failedPointer = nullptr;
            if (const long result = DetourTransactionCommitEx(&failedPointer); result == NO_ERROR) {
                IsPatched = false;

                if constexpr (ENABLE_DETOUR_LOGGING)
                    Debug("[Detour] (Restore) [Target: " ADDR_FMT " -> Original: " ADDR_FMT "]", reinterpret_cast<void*>(TargetAddress), OriginalFunction);

                if constexpr (WIN64)
                    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(TargetAddress), 14);
                else
                    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(TargetAddress), 5);

                return true;
            }
            else {
                const char* failMsg = failedPointer && *failedPointer ? static_cast<const char*>(*failedPointer) : "Unknown";
                Error("[Detour] Failed to restore! Error: %ld, Msg: %s", result, failMsg);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            const unsigned long code = GetExceptionCode();
            Error("[Detour] Exception occurred during Restore. Code: 0x%08X", code);
        }
        DetourTransactionAbort();
        return false;
    }


    bool Detour::Enable()
    {
        if (this->IsEnabled)
            return false;

        this->IsEnabled = true;
        return this->Apply();
    }

    bool Detour::Disable()
    {
        if (!this->IsEnabled)
            return false;

        this->IsEnabled = false;
        return this->Restore();
    }
}