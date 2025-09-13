// Copyright(C) 2025 0xKate - MIT License

#pragma once

namespace ByteWeaver
{
    class Patch {
    public:
        bool IsEnabled;
        bool IsPatched;
        uintptr_t TargetAddress;
        std::vector<uint8_t> PatchBytes;
        std::vector<uint8_t> OriginalBytes;

        Patch(uintptr_t patchAddress, std::vector<uint8_t> patchBytes);

        bool Apply();
        bool Restore();
        bool Enable();
        bool Disable();
    };
}