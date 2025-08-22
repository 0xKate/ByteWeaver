// Copyright(C) 2025 0xKate - MIT License

#include "ByteWeaver.h"
#include "AddressDB.h"

namespace ByteWeaver {

    // ---- static storage ----
    std::unordered_map<AddressDB::Key, AddressEntry, AddressDB::KeyHash> AddressDB::database_{};
    std::shared_mutex AddressDB::mutex_{};

    // ---- add ----
    void AddressDB::Add(AddressEntry entry) {
        Key key{ entry.symbolName, entry.moduleName };
        std::unique_lock lock(mutex_);
        auto it = database_.find(key);
        if (it == database_.end()) {
            database_.emplace(std::move(key), std::move(entry));
        }
        else {
            database_.erase(it);  // remove old (non-assignable) value
            database_.emplace(std::move(key), std::move(entry)); // insert new one
        }
    }

    void AddressDB::Add(std::string symbolName, std::wstring moduleName, bool isSymbolExport) {
        Add(AddressEntry(std::move(symbolName), std::move(moduleName), isSymbolExport));
    }

    void AddressDB::AddWithKnownAddress(std::string symbolName, std::wstring moduleName, uintptr_t address, bool isSymbolExport) {
        Add(AddressEntry::WithKnownAddress(std::move(symbolName),
            std::move(moduleName),
            address,
            isSymbolExport));
    }

    void AddressDB::AddWithKnownOffset(std::string symbolName, std::wstring moduleName, uintptr_t offset, bool isSymbolExport) {
        Add(AddressEntry::WithKnownOffset(std::move(symbolName),
            std::move(moduleName),
            offset,
            isSymbolExport));
    }

    void AddressDB::AddWithScanPattern(std::string symbolName, std::wstring moduleName, std::string pattern, bool isSymbolExport) {
        Add(AddressEntry::WithScanPattern(std::move(symbolName),
            std::move(moduleName),
            std::move(pattern),
            isSymbolExport));
    }

    // ---- find ----
    AddressEntry* AddressDB::Find(const std::string& symbolName, const std::wstring& moduleName) {
        return Find(Key{ symbolName, moduleName });
    }

    AddressEntry* AddressDB::Find(const Key& key) {
        std::shared_lock lock(mutex_);
        auto it = database_.find(key);
        return (it == database_.end()) ? nullptr : &it->second;
    }

    // ---- management ----
    bool AddressDB::Remove(const std::string& symbolName, const std::wstring& moduleName) {
        return Remove(Key{ symbolName, moduleName });
    }

    bool AddressDB::Remove(const Key& key) {
        std::unique_lock lock(mutex_);
        return database_.erase(key) > 0;
    }

    void AddressDB::Clear() {
        std::unique_lock lock(mutex_);
        database_.clear();
    }

    void AddressDB::UpdateAll()
    {
        for (auto& [key, value] : AddressDB::Mutate()) {
            HMODULE hMod = GetModuleHandleW(key.second.c_str());
            if (!hMod) {
                error("[AddressScanner] Module %ls not loaded yet.", key.second.c_str());
                continue;
            }
            value.SetModuleBase((uintptr_t)hMod);
            value.Update();
        }
    }

    // ---- debug ----
    void AddressDB::DumpAll() {
        std::shared_lock lock(mutex_);
        for (auto& kv : database_) {
            kv.second.Dump();
        }
    }

    bool AddressDB::VerifyAll()
    {
        bool allGood = true;

        debug("[AddressDB] Verifying all entries...");

        for (auto& [key, entry] : AddressDB::Mutate())
        {
            if (entry.Verify()) {
                debug("[AddressDB] %-17s : OK (0x%016llx)",
                    entry.symbolName.c_str(),
                    entry.targetAddress);
                continue;
            }

            allGood = false;

            const uintptr_t oldAddress = entry.targetAddress;
            const uintptr_t oldModuleBase = entry.moduleAddress;
            const uintptr_t oldOffset = entry.knownOffset.value_or(0);

            const auto updatedAddress = entry.Update();
            if (updatedAddress.has_value()) {
                warn("[AddressDB] %-17s : UPDATED -> 0x%016llx (was 0x%016llx)",
                    entry.symbolName.c_str(),
                    updatedAddress.value(),
                    oldAddress);

                debug("[AddressDB] %-17s : base 0x%016llx -> 0x%016llx, offset 0x%llx -> 0x%llx",
                    entry.symbolName.c_str(),
                    oldModuleBase,
                    entry.moduleAddress,
                    oldOffset,
                    entry.knownOffset.value_or(0));
            }
            else {
                error("[AddressDB] %-17s : VERIFY FAILED and UPDATE FAILED (module=%ls)",
                    entry.symbolName.c_str(),
                    entry.moduleName.c_str());
            }
        }

        if (allGood) {
            info("[AddressDB] All entries verified successfully.");
        }
        else {
            warn("[AddressDB] One or more entries failed verification. See messages above.");
            AddressDB::DumpAll();
        }

        return allGood;
    }
}