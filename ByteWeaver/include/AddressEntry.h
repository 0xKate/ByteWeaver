// Copyright(C) 2025 0xKate - MIT License

#pragma once

namespace ByteWeaver {

    // Represents a single address entry
    class AddressEntry {
    public:
        // Required identity
        const std::string  SymbolName;
        const std::wstring ModuleName;

        // Optional ways to resolve the address
        bool IsSymbolExport = true;
        std::optional<uintptr_t> KnownOffset;
        std::optional<std::string> ScanPattern;

        // Resolved data
        uintptr_t ModuleAddress = 0x0;
        uintptr_t TargetAddress = 0x0;

        // --- Constructors ---
        AddressEntry(std::string symbolName, std::wstring moduleName);
        static AddressEntry WithKnownAddress(std::string symbolName, std::wstring moduleName, uintptr_t address);
        static AddressEntry WithKnownOffset(std::string symbolName, std::wstring moduleName, uintptr_t offset);
        static AddressEntry WithScanPattern(std::string symbolName, std::wstring moduleName, const std::string& pattern);

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
        std::optional<std::vector<std::optional<uint8_t>>> _ScanBytes;
    };

}