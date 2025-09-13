// Copyright(C) 2025 0xKate - MIT License

#include <ByteWeaver.h>
#include <WinPatch.h>

namespace ByteWeaver
{
    Patch::Patch(const uintptr_t patchAddress, std::vector<uint8_t> patchBytes)
        : IsEnabled(false), IsPatched(false), TargetAddress(patchAddress), PatchBytes(std::move(patchBytes))
    {
        OriginalBytes.resize(this->PatchBytes.size());
    }

    bool Patch::Apply()
    {
        if (this->IsPatched)
            return true;
        
        DWORD oldProtection;
        DWORD _;
        const auto targetPointer = reinterpret_cast<void*>(TargetAddress);

        if (const bool result = VirtualProtect(targetPointer, PatchBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtection); !result) {
            const DWORD errCode = GetLastError();

            char buf[256];
            FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr,
                errCode,
                0,
                buf,
                sizeof(buf),
                nullptr
            );

            Error("[Patch] Failed to set permissions at " ADDR_FMT " (size: %zu). Error %lu: %s",
                targetPointer,
                PatchBytes.size(),
                errCode,
                buf);

            return false;
        }                

        __try {
            memcpy(OriginalBytes.data(), targetPointer, PatchBytes.size());         // Save original bytes
            memcpy(targetPointer, PatchBytes.data(), PatchBytes.size());            // Apply patch
            VirtualProtect(targetPointer, PatchBytes.size(), oldProtection, &_);    // Restore old protection

            if constexpr (ENABLE_PATCH_LOGGING)
                Debug("[Patch] (Apply) [Address: " ADDR_FMT ", Length: %zu]", TargetAddress, PatchBytes.size());

            FlushInstructionCache(GetCurrentProcess(), targetPointer, OriginalBytes.size());

            this->IsPatched = true;
            return true;

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            const DWORD code = GetExceptionCode();
            Error("[Patch] Exception writing patch at " ADDR_FMT " (Length: %zu): 0x%08x",
                targetPointer,
                PatchBytes.size(),
                code);

            return false;
        }
    }

    bool Patch::Restore()
    {
        if (!this->IsPatched)
            return true;

        DWORD oldProtection;
        DWORD _;
        const auto targetPointer = reinterpret_cast<void*>(TargetAddress);

        if (const bool result = VirtualProtect(targetPointer, OriginalBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtection); !result) {
            const DWORD errCode = GetLastError();

            char buf[256];
            FormatMessageA(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr,
                errCode,
                0,
                buf,
                sizeof(buf),
                nullptr
            );

            Error("[Patch] Failed to set permissions at " ADDR_FMT " (size: %zu). Error %lu: %s",
                TargetAddress,
                OriginalBytes.size(),
                errCode,
                buf);

            return false;
        }

        __try {
            memcpy(targetPointer, OriginalBytes.data(), OriginalBytes.size());            // Restore original bytes
            VirtualProtect(targetPointer, OriginalBytes.size(), oldProtection, &_);       // Restore old protection

            if constexpr (ENABLE_PATCH_LOGGING)
                Debug("[Patch] (Restore) [Address: " ADDR_FMT ", Length: %zu]", TargetAddress, OriginalBytes.size());

            FlushInstructionCache(GetCurrentProcess(), targetPointer, OriginalBytes.size());

            this->IsPatched = false;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            const DWORD code = GetExceptionCode();
            Error("[Patch] Exception restoring patch at " ADDR_FMT " (Length: %zu): 0x%08X ",
                TargetAddress,
                OriginalBytes.size(),
                code);

            return false;
        }        
    }

    bool Patch::Enable()
    {
        if (this->IsEnabled)
            return false;

        this->IsEnabled = true;
        return Apply();
    }

    bool Patch::Disable()
    {
        if (!this->IsEnabled)
            return false;

        this->IsEnabled = false;
        return Restore();
    }
}