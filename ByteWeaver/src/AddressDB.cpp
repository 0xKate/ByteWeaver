// Copyright(C) 2025 0xKate - MIT License

#include "ByteWeaverPCH.h"
#include "AddressDB.h"

namespace ByteWeaver {

    // ---- static storage ----
    std::unordered_map<AddressDB::Key, AddressEntry, AddressDB::KeyHash> AddressDB::_Database{};
    std::shared_mutex AddressDB::_Mutex{};

    // ---- add ----
    void AddressDB::Add(AddressEntry entry) {
        Key key{ entry.SymbolName, entry.ModuleName };
        std::unique_lock lock(_Mutex);
        if (const auto it = _Database.find(key); it == _Database.end()) {
            _Database.emplace(std::move(key), std::move(entry));
        }
        else {
            _Database.erase(it);  // remove old (non-assignable) value
            _Database.emplace(std::move(key), std::move(entry)); // insert new one
        }
    }

    void AddressDB::Add(std::string symbolName, std::wstring moduleName) {
        Add(AddressEntry(std::move(symbolName), std::move(moduleName)));
    }

    void AddressDB::AddWithKnownAddress(std::string symbolName, std::wstring moduleName, const uintptr_t address) {
        Add(AddressEntry::WithKnownAddress(std::move(symbolName), std::move(moduleName), address));
    }

    void AddressDB::AddWithKnownOffset(std::string symbolName, std::wstring moduleName, const uintptr_t offset) {
        Add(AddressEntry::WithKnownOffset(std::move(symbolName),
            std::move(moduleName),
            offset));
    }

    void AddressDB::AddWithScanPattern(std::string symbolName, std::wstring moduleName, std::string pattern) {
        Add(AddressEntry::WithScanPattern(std::move(symbolName),
            std::move(moduleName),
            std::move(pattern)));
    }

    // ---- find ----
    AddressEntry* AddressDB::Find(const std::string& symbolName, const std::wstring& moduleName) {
        return Find(Key{ symbolName, moduleName });
    }

    AddressEntry* AddressDB::Find(const Key& key) {
        std::shared_lock lock(_Mutex);
        const auto it = _Database.find(key);
        return it == _Database.end() ? nullptr : &it->second;
    }

    // ---- management ----
    bool AddressDB::Remove(const std::string& symbolName, const std::wstring& moduleName) {
        return Remove(Key{ symbolName, moduleName });
    }

    bool AddressDB::Remove(const Key& key) {
        std::unique_lock lock(_Mutex);
        return _Database.erase(key) > 0;
    }

    void AddressDB::Clear() {
        std::unique_lock lock(_Mutex);
        _Database.clear();
    }

    void AddressDB::UpdateAll()
    {
        for (auto& [key, value] : Mutate()) {
            HMODULE hMod = GetModuleHandleW(key.second.c_str());
            if (!hMod) {
                Error("[AddressScanner] Module %ls not loaded yet.", key.second.c_str());
                continue;
            }
            value.SetModuleBase(reinterpret_cast<uintptr_t>(hMod));
            value.Update();
        }
    }

    // ---- debug ----
    void AddressDB::DumpAll() {
        std::shared_lock lock(_Mutex);
        Debug("[AddressDB] Dumping database...");
        for (auto& val : _Database | std::views::values) {
            val.Dump();
        }
        Debug("[AddressDB] Database dump complete.\n");
    }

    bool AddressDB::VerifyAll()
    {
        bool allGood = true;

        Debug("[AddressDB] Verifying all entries...");

        for (auto& [key, entry] : Mutate())
        {
            if (entry.Verify()) {
                Debug("[AddressDB] %-17s : OK (" ADDR_FMT ")",
                    entry.SymbolName.c_str(),
                    entry.TargetAddress);
                continue;
            }

            allGood = false;

            const uintptr_t oldAddress = entry.TargetAddress;
            const uintptr_t oldModuleBase = entry.ModuleAddress;
            const uintptr_t oldOffset = entry.KnownOffset.value_or(0);

            if (const auto updatedAddress = entry.Update(); updatedAddress.has_value()) {
                Warn("[AddressDB] %-17s : UPDATED -> " ADDR_FMT " (was " ADDR_FMT ")",
                    entry.SymbolName.c_str(),
                    updatedAddress.value(),
                    oldAddress);

                Debug("[AddressDB] %-17s : base " ADDR_FMT " -> " ADDR_FMT ", offset 0x%llx -> 0x%llx",
                    entry.SymbolName.c_str(),
                    oldModuleBase,
                    entry.ModuleAddress,
                    oldOffset,
                    entry.KnownOffset.value_or(0));
            }
            else {
                Error("[AddressDB] %-17s : VERIFY FAILED and UPDATE FAILED (module=%ls)",
                    entry.SymbolName.c_str(),
                    entry.ModuleName.c_str());
            }
        }

        if (allGood) {
            Debug("[AddressDB] All entries verified successfully.\n");
        }
        else {
            Warn("[AddressDB] One or more entries failed verification. See messages above.\n");
            DumpAll();
        }

        return allGood;
    }
}
