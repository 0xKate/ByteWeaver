// Copyright(C) 2025 0xKate - MIT License

#include "ByteWeaver.h"
#include "SigScanner.h"

namespace ByteWeaver {

    std::vector<std::optional<uint8_t>> SigScanner::ParsePattern(const std::string& patternStr) {
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

    std::optional<uintptr_t> SigScanner::FindSignature(
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


    std::optional<uintptr_t> SigScanner::ModuleSearch(std::wstring moduleName, std::string signature, size_t skipCount, std::string title) {
        HMODULE hMod = GetModuleHandleW(moduleName.c_str());
        if (!hMod) {
            error(" Module %ls not loaded yet.", moduleName.c_str());
            return std::nullopt;
        }

        uint8_t* moduleAddress = reinterpret_cast<uint8_t*>(hMod);
        IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(moduleAddress);
        IMAGE_NT_HEADERS64* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(moduleAddress + dos->e_lfanew);
        size_t moduleSize = nt->OptionalHeader.SizeOfImage;

        std::vector<std::optional<uint8_t>> pattern = SigScanner::ParsePattern(signature);

        auto sigAddress = SigScanner::FindSignature(moduleAddress, moduleSize, pattern, skipCount);
        if (sigAddress.has_value()) {
            debug(
                "[SigScanner] %s Signature found!\n"
                " Module: % ls\n"
                " Base Address : 0x%016llx\n"
                " Module Size  : 0x%llx\n"
                " Sig Address  : 0x%016llx\n"
                " Offset       : 0x%llx\n",
                title.c_str(),
                moduleName.c_str(),
                moduleAddress,
                moduleSize,
                reinterpret_cast<void*>(sigAddress.value()),
                sigAddress.value() - reinterpret_cast<uintptr_t>(moduleAddress)
            );
        }
        else {
            warn(" Failed to find signature in module %ls", moduleName.c_str());
        }
        return sigAddress;
    }
}