// Copyright(C) 2025 0xKate - MIT License

#include <WinPatch.h>

namespace ByteWeaver
{
    Patch::Patch(const uintptr_t patchAddress, std::vector<uint8_t> patchBytes) : PatchBytes(std::move(patchBytes))
    {
        this->IsModified = false;
        this->TargetAddress = patchAddress;
        this->Size = this->PatchBytes.size();
        this->Type = ModType::Patch;
        this->OriginalBytes.resize(Size);
    }

    bool Patch::Apply()
    {
        if (this->IsModified)
            return true;

        if (TargetAddress == 0x0) {
            Error("[Patch] Tried to apply patch with invalid address!");
            return false;
        }

        DWORD oldProtection;
        DWORD _;

        const auto targetPointer = reinterpret_cast<void*>(TargetAddress);

        if (const bool result = VirtualProtect(targetPointer, Size, PAGE_EXECUTE_READWRITE, &oldProtection); !result) {
            const DWORD errCode = GetLastError();
            char buffer[256];
            FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, nullptr, errCode, 0, buffer, 256, nullptr);
                Error("[Patch] Failed to set permissions%s%s at " ADDR_FMT " (size: %zu). Error %lu: %s",
                    !this->Key.empty() ? " for " : "",
                    !this->Key.empty() ? this->Key.c_str() : "",
                    targetPointer,
                    Size,
                    errCode,
                    buffer
                    );
            return false;
        }

        __try {
            memcpy(OriginalBytes.data(), targetPointer, Size);         // Save original bytes
            memcpy(targetPointer, PatchBytes.data(), Size);            // Apply patch
            VirtualProtect(targetPointer, Size, oldProtection, &_);    // Restore old protection

            if constexpr (BYTEWEAVER_ENABLE_LOGGING) {
                if (!this->Key.empty()) {
                    Debug("[Patch] (Apply) [Address: " ADDR_FMT ", Size: %zu, Key: %s]", TargetAddress, Size, Key.c_str());
                } else {
                    Debug("[Patch] (Apply) [Address: " ADDR_FMT ", Size: %zu]", TargetAddress, Size);
                    Warn("[Patch] WARNING: Applied unmanaged patch @" ADDR_FMT, TargetAddress);
                }
            }

            FlushInstructionCache(GetCurrentProcess(), targetPointer, Size);

            this->IsModified = true;
            return true;

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            const DWORD code = GetExceptionCode();
            Error("[Patch] Exception writing patch at " ADDR_FMT " (Size: %zu): 0x%08x",
                targetPointer,
                Size,
                code);

            return false;
        }
    }

    bool Patch::Restore()
    {
        if (!this->IsModified)
            return true;

        DWORD oldProtection;
        DWORD _;
        const auto targetPointer = reinterpret_cast<void*>(TargetAddress);

        if (const bool result = VirtualProtect(targetPointer, Size, PAGE_EXECUTE_READWRITE, &oldProtection); !result) {
            const DWORD errCode = GetLastError();
            char buffer[256];
            FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, nullptr, errCode, 0, buffer, 256, nullptr);
            Error("[Patch] Failed to set permissions%s%s at " ADDR_FMT " (size: %zu). Error %lu: %s",
                !this->Key.empty() ? " for " : "",
                !this->Key.empty() ? this->Key.c_str() : "",
                targetPointer,
                Size,
                errCode,
                buffer
                );
        }

        __try {
            memcpy(targetPointer, OriginalBytes.data(), Size);            // Restore original bytes
            VirtualProtect(targetPointer, Size, oldProtection, &_);       // Restore old protection

            if constexpr (BYTEWEAVER_ENABLE_LOGGING) {
                if (!this->Key.empty()) {
                    Debug("[Patch] (Restore) [Address: " ADDR_FMT ", Size: %zu, Key: %s]", TargetAddress, Size, Key.c_str());
                } else {
                    Debug("[Patch] (Restore) [Address: " ADDR_FMT ", Size: %zu]", TargetAddress, Size);
                }
            }

            FlushInstructionCache(GetCurrentProcess(), targetPointer, Size);

            this->IsModified = false;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            const DWORD code = GetExceptionCode();
            Error("[Patch] Exception restoring patch at " ADDR_FMT " (Size: %zu): 0x%08X ",
                TargetAddress,
                Size,
                code);

            return false;
        }        
    }
}