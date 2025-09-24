// Copyright(C) 2025 0xKate - MIT License

#include <ByteWeaver.h>
#include <WinDetour.h>
#include <detours.h>

namespace ByteWeaver
{
    #if defined(_WIN64)
        constexpr SIZE_T DETOUR_MIN_SIZE = 14;
    #else
        constexpr SIZE_T DETOUR_MIN_SIZE = 5;
    #endif

    SIZE_T GetDetourPatchSize(void* funcPointer)
    {
        auto* bytePointer = static_cast<uint8_t*>(funcPointer);
        SIZE_T nBytes = 0;
        LONG extra = 0;

        while (nBytes < DETOUR_MIN_SIZE)
        {
            auto* pNext = static_cast<uint8_t*>(DetourCopyInstruction(
                nullptr,
                nullptr,
                bytePointer,
                nullptr,
                &extra));

            const SIZE_T instrLen = pNext - bytePointer;  // Remove the + extra
            nBytes += instrLen;
            bytePointer = pNext;
        }
        return nBytes;
    }


    Detour::Detour(const uintptr_t targetAddress, PVOID* originalFunction, PVOID detourFunction)
    {
        this->TargetAddress = targetAddress;
        this->IsPatched = false;
        this->OriginalFunction = originalFunction;
        this->DetourFunction = detourFunction;
        this->IsEnabled = false;
        this->Size = GetDetourPatchSize(reinterpret_cast<void*>(targetAddress));
        if constexpr (ENABLE_DETOUR_LOGGING)
            Debug("[Detour] Got patch size of %d for " ADDR_FMT, this->Size, targetAddress);
    }

    bool Detour::Apply()
    {
        if (IsPatched)
            return true;

        // Validate inputs
        if (!OriginalFunction || !DetourFunction || TargetAddress == 0) {
            Error("[Detour] Invalid parameters: " ADDR_FMT, TargetAddress);
            return false;
        }

        // Verify memory is executable
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(reinterpret_cast<void*>(TargetAddress), &mbi, sizeof(mbi)) == 0 ||
            !(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            Error("[Detour] Target memory is not executable: " ADDR_FMT, TargetAddress);
            return false;
            }

        DetourTransactionBegin();

        __try {
            this->OriginalBytes.clear();
            this->OriginalBytes.resize(this->Size);
            memcpy(this->OriginalBytes.data(), reinterpret_cast<void*>(TargetAddress), this->Size);

            DetourUpdateThread(GetCurrentThread());
            DetourAttach(OriginalFunction, DetourFunction);

            PVOID* failedPointer = nullptr;
            const LONG result = DetourTransactionCommitEx(&failedPointer);
            if (result == NO_ERROR) {
                if constexpr (ENABLE_DETOUR_LOGGING)
                    Debug("[Detour] (Apply) [Target: " ADDR_FMT " -> Detour: " ADDR_FMT "]",
                          reinterpret_cast<void*>(TargetAddress), DetourFunction);
                IsPatched = true;
                // Removed FlushInstructionCache - Detours handles this
                return true;
            }

            if (failedPointer) {
                Error("[Detour] Failed to apply! Failed pointer: %p, Error code: 0x%08X", *failedPointer, result);
            } else {
                Error("[Detour] Failed to apply! Unknown pointer. Error code: 0x%08X", result);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            const unsigned long code = GetExceptionCode();
            Error("[Detour] Exception occurred during apply. Code: 0x%08X", code);
        }

        DetourTransactionAbort();
        return false;
    }

    bool Detour::Restore()
    {
        if (!IsPatched)
            return true;

        // Validate we have what we need
        if (!OriginalFunction || !DetourFunction) {
            Error("[Detour] Invalid function pointers for restore: " ADDR_FMT, TargetAddress);
            IsPatched = false;
            return false;
        }

        DetourTransactionBegin();

        __try {
            DetourUpdateThread(GetCurrentThread());
            DetourDetach(OriginalFunction, DetourFunction);

            PVOID* failedPointer = nullptr;
            const LONG result = DetourTransactionCommitEx(&failedPointer);
            if (result == NO_ERROR) {
                IsPatched = false;

                if constexpr (ENABLE_DETOUR_LOGGING)
                    Debug("[Detour] (Restore) [Target: " ADDR_FMT " -> Original: " ADDR_FMT "]",
                          reinterpret_cast<void*>(TargetAddress), *OriginalFunction); // Dereference OriginalFunction

                // Remove FlushInstructionCache - Detours handles this internally
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