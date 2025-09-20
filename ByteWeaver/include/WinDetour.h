// Copyright(C) 2025 0xKate - MIT License

#pragma once

namespace ByteWeaver {

    class Detour {
    public:
        bool IsEnabled;
        bool IsPatched;
        uintptr_t TargetAddress;
        PVOID* OriginalFunction;
        PVOID  DetourFunction;
        std::vector<uint8_t> OriginalBytes;
        size_t Size;
        Detour(uintptr_t targetAddress, PVOID* originalFunction, PVOID detourFunction);

        bool Apply();
        bool Restore();
        bool Enable();
        bool Disable();
    };
}