// Copyright(C) 2025 0xKate - MIT License

#include <ByteWeaver.h>
#include <WinDetour.h>
#include <detours.h>

namespace ByteWeaver
{
    Detour::Detour(const uintptr_t targetAddress, PVOID* originalFunction, PVOID detourFunction)
    {
        this->TargetAddress = targetAddress;
        this->IsPatched = false;
        this->OriginalFunction = originalFunction;
        this->DetourFunction = detourFunction;
        this->IsEnabled = false;
        this->Size = WIN64 ? 14 : 5;
    }

    bool Detour::Apply()
    {
        if (IsPatched)
            return true;

        DetourTransactionBegin();

        __try {
            this->OriginalBytes.clear();
            this->OriginalBytes.resize(this->Size);
            memcpy(this->OriginalBytes.data(), reinterpret_cast<void*>(TargetAddress), this->Size);

            DetourUpdateThread(GetCurrentThread());
            DetourAttach(OriginalFunction, DetourFunction);

            PVOID* failedPointer = nullptr;
            const LONG result = DetourTransactionCommitEx(&failedPointer);
            if ( result == NO_ERROR) {
                if constexpr (ENABLE_DETOUR_LOGGING)
                    Debug("[Detour] (Apply) [Target: " ADDR_FMT " -> Detour: " ADDR_FMT "]", reinterpret_cast<void*>(TargetAddress), DetourFunction);
                IsPatched = true;

                FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(TargetAddress), this->Size);

                return true;
            }
            if (failedPointer) {
                Error("[Detour] Failed to apply! Failed pointer: %p, Error code: 0x%08X", *failedPointer, result);
            } else {
                Error("[Detour] Failed to apply! Unknown pointer. Error code: 0x%08X", result);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            const DWORD code = GetExceptionCode();
            Error("[Detour] Exception occurred during apply. Code: 0x%08X", code);
        }

        DetourTransactionAbort();

        return false;
    }

    bool Detour::Restore()
    {
        if (!IsPatched)
            return true;

        DetourTransactionBegin();

        __try {
            DetourUpdateThread(GetCurrentThread());
            DetourDetach(OriginalFunction, DetourFunction);

            PVOID* failedPointer = nullptr;
            const long result = DetourTransactionCommitEx(&failedPointer);
            if (result == NO_ERROR) {
                IsPatched = false;

                if constexpr (ENABLE_DETOUR_LOGGING)
                    Debug("[Detour] (Restore) [Target: " ADDR_FMT " -> Original: " ADDR_FMT "]", reinterpret_cast<void*>(TargetAddress), OriginalFunction);

                FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(TargetAddress), this->Size);

                return true;
            }
            if (failedPointer) {
                Error("[Detour] Failed to restore! Failed pointer: %p, Error code: 0x%08X", *failedPointer, result);
            } else {
                Error("[Detour] Failed to restore! Unknown pointer. Error code: 0x%08X", result);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            const unsigned long code = GetExceptionCode();
            Error("[Detour] Exception occurred during restore. Code: 0x%08X", code);
        }

        DetourTransactionAbort();

        return false;
    }

    bool Detour::Enable() {
        if (this->IsEnabled)
            return false;

        this->IsEnabled = true;
        return this->Apply();
    }

    bool Detour::Disable() {
        if (!this->IsEnabled)
            return false;

        this->IsEnabled = false;
        return this->Restore();
    }
}