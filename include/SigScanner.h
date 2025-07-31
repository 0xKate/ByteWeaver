// Copyright(C) 2025 0xKate - MIT License

#pragma once

namespace ByteWeaver {
    class SigScanner {
    public:
        static std::vector<std::optional<uint8_t>> ParsePattern(const std::string& patternStr);
        static std::optional<uintptr_t> FindSignature(uint8_t* base, size_t size, const std::vector<std::optional<uint8_t>>& pattern, size_t skipcount = 0);
        static std::optional<uintptr_t> ModuleSearch(std::wstring moduleName, std::string signature, size_t skipCount = 0, std::string title = std::string("UnknownName"));
    };
}
