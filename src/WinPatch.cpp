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
        if (!this->isPatched)
        {
            DWORD oldProtection;
            DWORD _;
            uint8_t* patchAddress = reinterpret_cast<uint8_t*>(targetAddress);

            BOOL result = VirtualProtect(patchAddress, patchBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtection);
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
                    patchAddress,
                    patchBytes.size(),
                    errCode,
                    buf);

                return false;
            }                

            __try
            {
                memcpy(originalBytes.data(), patchAddress, patchBytes.size());   // Save original bytes
                memcpy(patchAddress, patchBytes.data(), patchBytes.size());      // Apply patch
                FlushInstructionCache(GetCurrentProcess(), patchAddress, originalBytes.size());
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                DWORD code = GetExceptionCode();

                const char* reason = "Unknown";
                switch (code)
                {
                case EXCEPTION_ACCESS_VIOLATION: reason = "Access Violation"; break;
                case EXCEPTION_IN_PAGE_ERROR:    reason = "In-page Error"; break;
                case EXCEPTION_GUARD_PAGE:       reason = "Guard Page Violation"; break;
                case EXCEPTION_ILLEGAL_INSTRUCTION: reason = "Illegal Instruction"; break;
                case EXCEPTION_PRIV_INSTRUCTION: reason = "Privileged Instruction"; break;
                case EXCEPTION_DATATYPE_MISALIGNMENT: reason = "Datatype Misalignment"; break;
                case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: reason = "Array Bounds Exceeded"; break;
                    // add more as needed
                }

                error("[Patch] Exception writing patch at 0x%016llx (Length: %zu): 0x%08x (%s)",
                    patchAddress,
                    patchBytes.size(),
                    code,
                    reason);

                return false;
            }


            VirtualProtect(patchAddress, patchBytes.size(), oldProtection, &_);

            if constexpr (ENABLE_PATCH_LOGGING)
                debug("[Patch] (Apply) [Address: 0x%016llx, Length: %zu]", patchAddress, patchBytes.size());

            this->isPatched = true;
            return true;
        }
        return true;
    }

    bool Patch::Restore()
    {
        if (!this->isPatched)
            return false;

        DWORD oldProtection;
        DWORD _;
        void* pTarget = reinterpret_cast<void*>(targetAddress);

        BOOL result = VirtualProtect(pTarget, originalBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtection);
        if (!result)
        {
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

            error("[Patch] Failed to change memory protection for restore at 0x%016llx (size: %zu). Error %lu: %s",
                reinterpret_cast<uintptr_t>(pTarget),
                originalBytes.size(),
                errCode,
                buf);

            return false;
        }

        __try
        {
            memcpy(pTarget, originalBytes.data(), originalBytes.size());
            FlushInstructionCache(GetCurrentProcess(), pTarget, originalBytes.size());
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DWORD code = GetExceptionCode();
            const char* reason = "Unknown";

            switch (code)
            {
            case EXCEPTION_ACCESS_VIOLATION: reason = "Access Violation"; break;
            case EXCEPTION_IN_PAGE_ERROR:    reason = "In-page Error"; break;
            case EXCEPTION_GUARD_PAGE:       reason = "Guard Page Violation"; break;
            case EXCEPTION_ILLEGAL_INSTRUCTION: reason = "Illegal Instruction"; break;
            case EXCEPTION_PRIV_INSTRUCTION: reason = "Privileged Instruction"; break;
            case EXCEPTION_DATATYPE_MISALIGNMENT: reason = "Datatype Misalignment"; break;
            case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: reason = "Array Bounds Exceeded"; break;
            }

            error("[Patch] Exception restoring memory at 0x%016llx (Length: %zu): 0x%08X (%s)",
                reinterpret_cast<uintptr_t>(pTarget),
                originalBytes.size(),
                code,
                reason);

            return false;
        }

        VirtualProtect(pTarget, originalBytes.size(), oldProtection, &_);

        if constexpr (ENABLE_PATCH_LOGGING)
            debug("[Patch] (Restore) [Address: 0x%016llx, Length: %zu]", pTarget, originalBytes.size());

        this->isPatched = false;
        return true;
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