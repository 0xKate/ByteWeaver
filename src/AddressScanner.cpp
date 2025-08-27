// Copyright(C) 2025 0xKate - MIT License

#include "ByteWeaver.h"
#include "AddressScanner.h"

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
        size_t size,
        const std::vector<std::optional<uint8_t>>& pattern,
        size_t skipCount)
    {
        size_t patternSize = pattern.size();
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
                if (foundCount < skipCount) {
                    ++foundCount;
                    continue;
                }
                return reinterpret_cast<uintptr_t>(&base[i]);
            }
        }
        return std::nullopt;
    }

    // ModuleSearch
    SearchResults AddressScanner::ModuleSearch(const std::wstring& moduleName, const std::string& symbolName, const std::vector<std::optional<uint8_t>> pattern, size_t skipCount)
    {
        HMODULE hMod = GetModuleHandleW(moduleName.c_str());
        if (!hMod) {
            error("[AddressScanner] Module %ls not loaded yet.", moduleName.c_str());
            return std::nullopt;
        }

        uint8_t* modulePointer = reinterpret_cast<uint8_t*>(hMod);
        IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(modulePointer);
        IMAGE_NT_HEADERS64* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(modulePointer + dos->e_lfanew);
        size_t moduleSize = nt->OptionalHeader.SizeOfImage;

        auto sigAddress = AddressScanner::FindSignature(modulePointer, moduleSize, pattern, skipCount);
        if (sigAddress.has_value()) {
            uintptr_t moduleAddress = reinterpret_cast<uintptr_t>(modulePointer);
            uintptr_t offset = sigAddress.value() - moduleAddress;
            if constexpr (BYTEWEAVER_ENABLE_PATTERN_SCAN_LOGGING)
                debug(
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
            return std::tuple<uintptr_t, uintptr_t, uintptr_t>(moduleAddress, sigAddress.value(), offset);
        }
        else {
            warn(" Failed to find signature in module %ls", moduleName.c_str());
            return std::nullopt;
        }
    }

    // ModuleSearch
    SearchResults AddressScanner::ModuleSearch(const std::wstring& moduleName, const std::string& symbolName, const std::string& signature, size_t skipCount) {
        std::vector<std::optional<uint8_t>> pattern = AddressScanner::ParsePattern(signature);
        return ModuleSearch(moduleName, symbolName, pattern);
    }

    // LookupExportAddress
    SearchResults AddressScanner::LookupExportAddress(const std::wstring& moduleName, const std::string& symbolName)
    {
        HMODULE hMod = GetModuleHandleW(moduleName.c_str());
        if (!hMod) {
            error("[AddressScanner] Module %ls not loaded yet.", moduleName.c_str());
            return std::nullopt;
        }

        FARPROC address = GetProcAddress(hMod, symbolName.c_str());
        if (!address) {
            error("[AddressScanner] Failed to find symbol %s in module %ls y !", symbolName.c_str(), moduleName.c_str());
            return std::nullopt;
        }

        if constexpr (BYTEWEAVER_ENABLE_PATTERN_SCAN_LOGGING) {
            uint8_t* modulePointer = reinterpret_cast<uint8_t*>(hMod);
            IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(modulePointer);
            IMAGE_NT_HEADERS64* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(modulePointer + dos->e_lfanew);
            size_t moduleSize = nt->OptionalHeader.SizeOfImage;
            uintptr_t moduleAddress = reinterpret_cast<uintptr_t>(modulePointer);
            uintptr_t offset = reinterpret_cast<uintptr_t>(address) - moduleAddress;

            debug(
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
                (uintptr_t)address,
                offset
            );
        }

        return std::tuple<uintptr_t, uintptr_t, uintptr_t>((uintptr_t)hMod, (uintptr_t)address, (uintptr_t)address - (uintptr_t)hMod);
    }
}