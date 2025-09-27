#pragma once

#include <ByteWeaver.h>

namespace ByteWeaver
{
    enum class ModType : uint8_t {
        Detour,
        Patch,
        Unspecified = 0xFF
    };

    class MemoryModification
    {
    protected:
        // Only derived classes can construct
        MemoryModification() = default;

    public:
        virtual ~MemoryModification() = default; // always virtual in base classes

        // Shared parameters
        bool IsModified = false;
        uintptr_t TargetAddress = NULL;
        std::vector<uint8_t> OriginalBytes{};
        size_t Size = 0;
        std::string Key{};
        uint16_t GroupID = 0x0000;
        ModType Type = ModType::Unspecified;

        // Pure virtual interface
        virtual bool Apply() = 0;
        virtual bool Restore() = 0;
    };

}