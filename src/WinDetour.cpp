// Copyright(C) 2025 0xKate - MIT License

#include <ByteWeaver.h>
#include <WinDetour.h>
#include <detours.h>

namespace ByteWeaver
{
    Detour::Detour(uintptr_t targetAddress, PVOID* originalFunction, PVOID detourFunction)
    {
        this->targetAddress = targetAddress;
        this->isPatched = false;
        this->originalFunction = originalFunction;
        this->detourFunction = detourFunction;
        this->isEnabled = false;
    }

    bool Detour::Apply()
    {
        if (isPatched)
            return true;

        __try
        {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(originalFunction, detourFunction);

            PVOID* failedPointer = nullptr;
            if (const LONG result = DetourTransactionCommitEx(&failedPointer); result == NO_ERROR) {
                if constexpr (ENABLE_DETOUR_LOGGING)
                    debug("[Detour] (Apply) [Target: " ADDR_FMT " -> Detour: " ADDR_FMT "]", reinterpret_cast<void*>(targetAddress), detourFunction);
                isPatched = true;

                if (Is64Bit)
                    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(targetAddress), 14);
                else
                    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(targetAddress), 5);

                return true;
            }
            else {
                const char* failMsg = failedPointer ? static_cast<const char*>(*failedPointer) : "Unknown";
                error("[Detour] Failed to apply! : %s", failMsg);             
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            const DWORD code = GetExceptionCode();
            error("[Detour] Exception occurred during Apply. Code: 0x%08X", code);
        }
        return false;
    }

    bool Detour::Restore()
    {
        if (!isPatched)
            return true;

        __try
        {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourDetach(originalFunction, detourFunction);

            PVOID* failedPointer = nullptr;
            LONG result = DetourTransactionCommitEx(&failedPointer);
            if (result == NO_ERROR) {
                isPatched = false;

                if constexpr (ENABLE_DETOUR_LOGGING)
                    debug("[Detour] (Restore) [Target: " ADDR_FMT " -> Original: " ADDR_FMT "]", reinterpret_cast<void*>(targetAddress), originalFunction);

                if (Is64Bit)
                    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(targetAddress), 14);
                else
                    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(targetAddress), 5);

                return true;
            }
            else {
                const char* failMsg = (failedPointer && *failedPointer) ? static_cast<const char*>(*failedPointer) : "Unknown";
                error("[Detour] Failed to restore! Error: %ld, Msg: %s", result, failMsg);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DWORD code = GetExceptionCode();
            error("[Detour] Exception occurred during Restore. Code: 0x%08X", code);
        }
        return false;
    }


    bool Detour::Enable()
    {
        if (this->isEnabled)
            return false;

        this->isEnabled = true;
        return this->Apply();
    }

    bool Detour::Disable()
    {
        if (!this->isEnabled)
            return false;

        this->isEnabled = false;
        return this->Restore();
    }
}