// Copyright(C) 2025 0xKate - MIT License

#pragma once

namespace ByteWeaver {
    class AddressScanner {
    public:
        static std::vector<std::optional<uint8_t>> ParsePattern(const std::string& patternStr);
        static std::optional<uintptr_t> FindSignature(uint8_t* base, size_t size, const std::vector<std::optional<uint8_t>>& pattern, size_t skipcount = 0);
        static std::optional<std::tuple<uintptr_t, uintptr_t, uintptr_t>> ModuleSearch(const std::string& symbolName, const std::wstring& moduleName, const std::string& signature, size_t skipCount = 0);
        static std::optional<std::tuple<uintptr_t, uintptr_t, uintptr_t>> ModuleSearch(const std::string& symbolName, const std::wstring& moduleName, const std::vector<std::optional<uint8_t>> pattern, size_t skipCount = 0);
        static std::optional<uintptr_t> LookupExportAddress(const std::wstring& moduleName, const std::string& symbolName);
    };
}

