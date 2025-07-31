// Copyright(C) 2025 0xKate - MIT License

#include <ByteWeaver.h>
#include <OffsetDB.h>


namespace ByteWeaver 
{
    std::unordered_map<std::string, Offset> OffsetDB::offsets = std::unordered_map<std::string, Offset>();

    Offset::Offset(const std::string& name, const std::wstring& moduleName, uintptr_t offset)
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
        for (auto& [name, off] : offsets) {
            HMODULE mod = GetModuleHandleW(off.moduleName.c_str());
            if (!mod) {
                error("Failed to get module base for: %ls", off.moduleName.c_str());
                continue;
            }
            off.moduleAddress = reinterpret_cast<uintptr_t>(mod);
        }
    }

    void OffsetDB::Add(const std::string& name, const std::wstring& moduleName, uintptr_t offset) {
        offsets[name] = Offset{ name, moduleName, offset };
    }

    bool OffsetDB::Erase(const std::string& name) {
        return offsets.erase(name) > 0;
    }

    const Offset* OffsetDB::Get(const std::string& name) {
        auto it = offsets.find(name);
        if (it != offsets.end())
            return &it->second;
        return nullptr;
    }

    void OffsetDB::DumpAll() {
        for (const auto& [name, off] : offsets) {
            off.Dump();
        }
    } 
}
