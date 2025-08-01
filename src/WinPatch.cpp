// Copyright(C) 2025 0xKate - MIT License

#include <ByteWeaver.h>
#include <WinPatch.h>

namespace ByteWeaver
{
    Patch::Patch(uintptr_t patchAddress, std::vector<uint8_t> patchBytes)
        : isEnabled(false), isPatched(false), targetAddress(patchAddress), patchBytes(std::move(patchBytes))
    {
        originalBytes.resize(this->patchBytes.size());
    }

    bool Patch::Apply()
    {
        if (this->isPatched)
            return true;
        
        DWORD oldProtection;
        DWORD _;
        void* targetPointer = reinterpret_cast<void*>(targetAddress);

        BOOL result = VirtualProtect(targetPointer, patchBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtection);
        if (!result) {
            DWORD errCode = GetLastError();

            char buf[256];
            FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr,
                errCode,
                0,
                buf,
                sizeof(buf),
                nullptr
            );

            error("[Patch] Failed to set permissions at 0x%016llx (size: %zu). Error %lu: %s",
                targetPointer,
                patchBytes.size(),
                errCode,
                buf);

            return false;
        }                

        __try {
            memcpy(originalBytes.data(), targetPointer, patchBytes.size());         // Save original bytes
            memcpy(targetPointer, patchBytes.data(), patchBytes.size());            // Apply patch                
            VirtualProtect(targetPointer, patchBytes.size(), oldProtection, &_);    // Restore old protection

            if constexpr (ENABLE_PATCH_LOGGING)
                debug("[Patch] (Apply) [Address: 0x%016llx, Length: %zu]", targetAddress, patchBytes.size());

            FlushInstructionCache(GetCurrentProcess(), targetPointer, originalBytes.size());

            this->isPatched = true;
            return true;

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DWORD code = GetExceptionCode();
            error("[Patch] Exception writing patch at 0x%016llx (Length: %zu): 0x%08x",
                targetPointer,
                patchBytes.size(),
                code);

            return false;
        }
    }

    bool Patch::Restore()
    {
        if (!this->isPatched)
            return true;

        DWORD oldProtection;
        DWORD _;
        void* targetPointer = reinterpret_cast<void*>(targetAddress);

        BOOL result = VirtualProtect(targetPointer, originalBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtection);
        if (!result) {
            DWORD errCode = GetLastError();

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

            error("[Patch] Failed to set permissions at 0x%016llx (size: %zu). Error %lu: %s",
                targetAddress,
                originalBytes.size(),
                errCode,
                buf);

            return false;
        }

        __try {
            memcpy(targetPointer, originalBytes.data(), originalBytes.size());            // Restore original bytes
            VirtualProtect(targetPointer, originalBytes.size(), oldProtection, &_);       // Restore old protection

            if constexpr (ENABLE_PATCH_LOGGING)
                debug("[Patch] (Restore) [Address: 0x%016llx, Length: %zu]", targetAddress, originalBytes.size());

            FlushInstructionCache(GetCurrentProcess(), targetPointer, originalBytes.size());

            this->isPatched = false;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DWORD code = GetExceptionCode();
            error("[Patch] Exception restoring patch at 0x%016llx (Length: %zu): 0x%08X ",
                targetAddress,
                originalBytes.size(),
                code);

            return false;
        }        
    }

    bool Patch::Enable()
    {
        if (this->isEnabled)
            return false;

        this->isEnabled = true;
        return Apply();
    }

    bool Patch::Disable()
    {
        if (!this->isEnabled)
            return false;

        this->isEnabled = false;
        return Restore();
    }
}