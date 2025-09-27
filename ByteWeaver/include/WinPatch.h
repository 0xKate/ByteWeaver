// Copyright(C) 2025 0xKate - MIT License

#pragma once

#include <MemoryModification.h>

namespace ByteWeaver
{
    class Patch final : public MemoryModification {
    public:
        std::vector<uint8_t> PatchBytes;


        Patch(uintptr_t patchAddress, std::vector<uint8_t> patchBytes);

        bool Apply() override;
        bool Restore() override;
    };
}