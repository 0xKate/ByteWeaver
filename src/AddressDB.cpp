// Copyright(C) 2025 0xKate - MIT License

#include "ByteWeaver.h"
#include "AddressDB.h"

namespace ByteWeaver {

    // ---- static storage ----
    std::unordered_map<AddressDB::Key, AddressEntry, AddressDB::KeyHash> AddressDB::database_;

    // ---- add ----
    void AddressDB::Add(AddressEntry entry) {
        Key key{ entry.symbolName, entry.moduleName };
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
        auto it = database_.find(key);
        return (it == database_.end()) ? nullptr : &it->second;
    }

    // ---- management ----
    bool AddressDB::Remove(const std::string& symbolName, const std::wstring& moduleName) {
        return Remove(Key{ symbolName, moduleName });
    }

    bool AddressDB::Remove(const Key& key) {
        return database_.erase(key) > 0;
    }

    void AddressDB::Clear() {
        database_.clear();
    }

    // ---- debug ----
    void AddressDB::DumpAll() {
        for (auto& kv : database_) {
            kv.second.Dump();
        }
    }
}