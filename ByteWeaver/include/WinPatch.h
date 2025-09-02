// Copyright(C) 2025 0xKate - MIT License

#pragma once

namespace ByteWeaver
{
    class Patch {
    public:
        bool isEnabled;
        bool isPatched;
        uintptr_t targetAddress;
        std::vector<uint8_t> patchBytes;
        std::vector<uint8_t> originalBytes;

        Patch(uintptr_t patchAddress, std::vector<uint8_t> patchBytes);

        bool Apply();
        bool Restore();
        bool Enable();
        bool Disable();
    };
}