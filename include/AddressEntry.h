// Copyright(C) 2025 0xKate - MIT License

#pragma once

namespace ByteWeaver {

    // Represents a single address entry
    class AddressEntry {
    public:
        // Required identity
        const std::string  symbolName;
        const std::wstring moduleName;

        // Optional ways to resolve the address
        const bool isSymbolExport = false;
        std::optional<uintptr_t> knownOffset;
        std::optional<std::string> scanPattern;

        // Resolved data
        uintptr_t moduleAddress = 0x0;
        uintptr_t targetAddress = 0x0;

        // --- Constructors ---
        AddressEntry(std::string symbolName, std::wstring moduleName, bool isSymbolExport = false);
        static AddressEntry WithKnownAddress(std::string symbolName, std::wstring moduleName, uintptr_t address, bool isSymbolExport = false);
        static AddressEntry WithKnownOffset(std::string symbolName, std::wstring moduleName, uintptr_t offset, bool isSymbolExport = false);
        static AddressEntry WithScanPattern(std::string symbolName, std::wstring moduleName, std::string pattern, bool isSymbolExport = false);

        // --- Setters ---
        void SetModuleBase(uintptr_t moduleAddress);
        void SetKnownAddress(uintptr_t targetAddress);
        void SetKnownOffset(uintptr_t offset);
        void SetScanPattern(const std::string& pattern);

        // --- Accessors ---
        std::optional<uintptr_t> Update();
        std::optional<uintptr_t> GetAddress() const;
        std::optional<uintptr_t> GetAddress();

        // --- Debugging ---
        void Dump() const;
        bool Verify() const;


    private:
        // Cached parsed scan bytes
        std::optional<std::vector<std::optional<uint8_t>>> scanBytes_;
    };

}