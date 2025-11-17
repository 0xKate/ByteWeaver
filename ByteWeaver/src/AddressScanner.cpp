// Copyright(C) 2025 0xKate - MIT License

#include <AddressScanner.h>

namespace ByteWeaver {
#ifndef BYTEWEAVER_ENABLE_PATTERN_SCAN_LOGGING
#define BYTEWEAVER_ENABLE_PATTERN_SCAN_LOGGING 0
#endif

    // ParsePattern
    std::vector<std::optional<uint8_t>> AddressScanner::ParsePattern(const std::string& patternStr) {
        std::vector<std::optional<uint8_t>> pattern;
        std::istringstream iss(patternStr);
        std::string byteStr;

        while (std::getline(iss, byteStr, ',')) {
            if (byteStr == "?" || byteStr == "??")
                pattern.push_back(std::nullopt);
            else
                pattern.push_back(static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16)));
        }
        return pattern;
    }

    // FindSignature
    std::optional<uintptr_t> AddressScanner::FindSignature(
        uint8_t* base,
        const size_t size,
        const std::vector<std::optional<uint8_t>>& pattern,
        const size_t skipCount)
    {
        const size_t patternSize = pattern.size();

        __try {
            size_t foundCount = 0;
            for (size_t i = 0; i <= size - patternSize; ++i) {
                bool match = true;
                for (size_t j = 0; j < patternSize; ++j) {
                    if (pattern[j].has_value() && base[i + j] != pattern[j].value()) {
                        match = false;
                        break;
                    }
                }

                if (match) {
                    if (skipCount != -1)
                        if (foundCount < skipCount) {
                            ++foundCount;
                            continue;
                        }
                    return reinterpret_cast<uintptr_t>(&base[i]);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            Error("[AddressScanner] Caught an exception: code=0x%X", GetExceptionCode());
        }

        return std::nullopt;
    }

    // ModuleSearch
    SearchResults AddressScanner::ModuleSearch(const std::wstring& moduleName, const std::string& symbolName, const std::vector<std::optional<uint8_t>>& pattern, const size_t skipCount)
    {
        const HMODULE hMod = GetModuleHandleW(moduleName.c_str());
        if (!hMod) {
            Error("[AddressScanner] Module %ls not loaded yet.", moduleName.c_str());
            return std::nullopt;
        }

        auto modulePointer = reinterpret_cast<uint8_t*>(hMod);
        const auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(modulePointer);
        const auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(modulePointer + dos->e_lfanew);
        const size_t moduleSize = nt->OptionalHeader.SizeOfImage;

        if (auto sigAddress = FindSignature(modulePointer, moduleSize, pattern, skipCount); sigAddress.has_value()) {
            uintptr_t moduleAddress = reinterpret_cast<uintptr_t>(modulePointer);
            uintptr_t offset = sigAddress.value() - moduleAddress;
            if constexpr (BYTEWEAVER_ENABLE_PATTERN_SCAN_LOGGING)
                Debug(
                    "[AddressScanner] %s Signature found!\n"
                    " Module: % ls\n"
                    " Base Address : " ADDR_FMT 
                    " Module Size  : 0x%zu\n"
                    " Sig Address  : " ADDR_FMT 
                    " Offset       : 0x%llx\n",
                    symbolName.c_str(),
                    moduleName.c_str(),
                    moduleAddress,
                    moduleSize,
                    sigAddress.value(),
                    offset
                );
            return std::tuple(moduleAddress, sigAddress.value(), offset);
        }
        Warn(" Failed to find signature in module %ls", moduleName.c_str());
        return std::nullopt;
    }

    // ModuleSearch
    SearchResults AddressScanner::ModuleSearch(const std::wstring& moduleName, const std::string& symbolName, const std::string& signature, const size_t skipCount) {
        const std::vector<std::optional<uint8_t>> pattern = ParsePattern(signature);
        return ModuleSearch(moduleName, symbolName, pattern, skipCount);
    }

    // LookupExportAddress
    SearchResults AddressScanner::LookupExportAddress(const std::wstring& moduleName, const std::string& symbolName)
    {
        HMODULE hMod = GetModuleHandleW(moduleName.c_str());
        if (!hMod) {
            Error("[AddressScanner] Module %ls not loaded yet.", moduleName.c_str());
            return std::nullopt;
        }

        FARPROC address = GetProcAddress(hMod, symbolName.c_str());
        if (!address) {
            Error("[AddressScanner] Failed to find symbol %s in module %ls y !", symbolName.c_str(), moduleName.c_str());
            return std::nullopt;
        }

        if constexpr (BYTEWEAVER_ENABLE_PATTERN_SCAN_LOGGING) {
            auto modulePointer = reinterpret_cast<uint8_t*>(hMod);
            auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(modulePointer);
            auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(modulePointer + dos->e_lfanew);
            size_t moduleSize = nt->OptionalHeader.SizeOfImage;
            uintptr_t moduleAddress = reinterpret_cast<uintptr_t>(modulePointer);
            uintptr_t offset = reinterpret_cast<uintptr_t>(address) - moduleAddress;

            Debug(
                "[AddressScanner] %s Symbol found!\n"
                " Module: % ls\n"
                " Base Address : " ADDR_FMT 
                " Module Size  : 0x%zu\n"
                " Sig Address  : " ADDR_FMT 
                " Offset       : 0x%llx\n",
                symbolName.c_str(),
                moduleName.c_str(),
                moduleAddress,
                moduleSize,
                reinterpret_cast<uintptr_t>(address),
                offset
            );
        }

        return std::tuple(reinterpret_cast<uintptr_t>(hMod), reinterpret_cast<uintptr_t>(address), reinterpret_cast<uintptr_t>(address) - reinterpret_cast<uintptr_t>(hMod));
    }
}