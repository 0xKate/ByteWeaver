// Copyright(C) 2025 0xKate - MIT License

#pragma once

namespace ByteWeaver {

    class Offset {
    private:
        std::string scanPattern;
        std::vector<std::optional<uint8_t>> scanBytes;

    public:
        std::string symbolName;
        std::wstring moduleName;
        uintptr_t moduleAddress;
        uintptr_t offset;

        Offset() = default;
        Offset(const std::string& symbolName, const std::wstring& moduleName, const std::string& scanPattern);
        Offset(const std::string& symbolName, const std::wstring& moduleName, uintptr_t offset);
        Offset(const std::string& symbolName, const std::wstring& moduleName);

        void SetScanPattern(const std::string scanPattern);
        std::optional<std::vector<std::optional<uint8_t>>> GetScanBytes() const;
        std::optional<uintptr_t> ScanForOffset();
        uintptr_t Address() const;
        void Dump() const;
    };

    class OffsetDB {
    public:
        static std::unordered_map<std::string, Offset> offsets;
        static void InitializeModuleBases();
        static void Add(const std::string& symbolName, const std::wstring& moduleName, const std::string& scanPattern);
        static void Add(const std::string& symbolName, const std::wstring& moduleName, uintptr_t offset);
        static void Add(const std::string& symbolName, const std::wstring& moduleName);
        
        static bool Erase(const std::string& symbolName);
        static const Offset* Get(const std::string& symbolName);
        static void DumpAll();
    };
}