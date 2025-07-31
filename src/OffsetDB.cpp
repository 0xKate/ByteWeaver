// Copyright(C) 2025 0xKate - MIT License

#include <ByteWeaver.h>
#include <OffsetDB.h>

namespace ByteWeaver{
    std::vector<Offset> OffsetDB::offsets = std::vector<Offset>();

    Offset::Offset(std::string_view name, std::wstring_view moduleName, uintptr_t offset)
        : name(name), moduleName(moduleName), offset(offset) {
    }

    uintptr_t Offset::Address() const {
        return moduleAddress + offset;
    }

    void Offset::Dump() const {
        debug(" --- %s Dump ---", name.c_str());
        debug(" Module Name   : %ls", moduleName.c_str());
        debug(" Module Base   : 0x%016llx", moduleAddress);
        debug(" Offset        : 0x%llx", offset);
        debug(" Final Address : 0x%016llx\n", Address());
    }

    void OffsetDB::InitializeModuleBases() {
        for (auto& off : OffsetDB::offsets) {
            HMODULE mod = GetModuleHandleW(off.moduleName.c_str());
            if (!mod) {
                error("Failed to get module base for: %ls", off.moduleName.c_str());
                continue;
            }
            off.moduleAddress = reinterpret_cast<uintptr_t>(mod);
        }
    }

    void OffsetDB::Add(const std::string& name, const std::wstring& moduleName, uintptr_t offset) {
        OffsetDB::offsets.emplace_back(name, moduleName, offset);
    }

    const Offset* OffsetDB::Get(const std::string& name) {
        for (const auto& off : OffsetDB::offsets) {
            if (off.name == name)
                return &off;
        }
        return nullptr;
    }

    void OffsetDB::DumpAll() {
        for (const auto& off : OffsetDB::offsets)
        {
            off.Dump();
        }
    }
}
