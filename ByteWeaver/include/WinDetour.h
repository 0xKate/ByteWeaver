// Copyright(C) 2025 0xKate - MIT License

#pragma once

#include <MemoryModification.h>

namespace ByteWeaver {

    class Detour final : public MemoryModification {
    public:
        PVOID* OriginalFunction;
        PVOID  DetourFunction;

        Detour(uintptr_t targetAddress, PVOID* originalFunction, PVOID detourFunction);

        bool Apply() override;
        bool Restore() override;
        bool Enable() override;
        bool Disable() override;
    };
}