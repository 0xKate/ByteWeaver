// Copyright(C) 2025 0xKate - MIT License

#pragma once

#include "AddressEntry.h"
namespace ByteWeaver {

    class AddressDB {
    public:
        AddressDB() = delete;
        AddressDB(const AddressDB&) = delete;
        AddressDB& operator=(const AddressDB&) = delete;

        // ----- Key type (symbolName, moduleName) -----
        using Key = std::pair<std::string, std::wstring>;

        // --- Read-only iterable view (holds shared lock for loop lifetime) ---
        class ReadView {
        public:
            ReadView() : lock_(mutex_) {}
            auto begin() const noexcept { return database_.cbegin(); }
            auto end()   const noexcept { return database_.cend(); }
        private:
            std::shared_lock<std::shared_mutex> lock_;
        };
        static ReadView Iterate() noexcept { return {}; }

        // ---- Mutable iterable view (unique lock) ----
        class WriteView {
        public:
            WriteView() : lock_(mutex_) {}
            auto begin() noexcept { return database_.begin(); }
            auto end()   noexcept { return database_.end(); }
        private:
            std::unique_lock<std::shared_mutex> lock_;
        };
        static WriteView Mutate() noexcept { return {}; }

        // ----- Basic add APIs -----
        static void Add(AddressEntry entry);  // uses entry.symbolName / entry.moduleName as key

        static void Add(std::string symbolName,
            std::wstring moduleName);

        static void AddWithKnownAddress(std::string symbolName,
            std::wstring moduleName,
            uintptr_t address);

        static void AddWithKnownOffset(std::string symbolName,
            std::wstring moduleName,
            uintptr_t offset);

        static void AddWithScanPattern(std::string symbolName,
            std::wstring moduleName,
            std::string pattern);

        // ----- Lookup -----
        static AddressEntry* Find(const std::string& symbolName, const std::wstring& moduleName);

        // Overloads using the composite key directly
        static AddressEntry* Find(const Key& key);

        // ----- Management -----
        static bool Remove(const std::string& symbolName, const std::wstring& moduleName);
        static bool Remove(const Key& key);
        static void Clear();
        static void UpdateAll();

        // ----- Debug -----
        static void DumpAll();
        static bool VerifyAll();

    private:
        struct KeyHash {
            size_t operator()(const Key& k) const noexcept {
                // simple combine of two hashes
                const size_t h1 = std::hash<std::string>{}(k.first);
                const size_t h2 = std::hash<std::wstring>{}(k.second);
                return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2));
            }
        };

        static std::unordered_map<Key, AddressEntry, KeyHash> database_;
        static std::shared_mutex mutex_;
    };

}


