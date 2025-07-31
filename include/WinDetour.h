#pragma once

namespace ByteWeaver {

    class Detour {
    public:
        bool isEnabled;
        bool isPatched;
        uintptr_t targetAddress;
        PVOID* originalFunction;
        PVOID  detourFunction;
        Detour(uintptr_t targetAddress, PVOID* originalFunction, PVOID detourFunction);

        bool Apply();
        bool Restore();
        bool Enable();
        bool Disable();
    };
}