// Copyright(C) 2025 0xKate - MIT License

#include "ByteWeaver.h"
#include "AddressEntry.h"
#include "AddressScanner.h"

namespace ByteWeaver {

    // --- Constructors ---
    AddressEntry::AddressEntry(std::string symbolName, std::wstring moduleName, bool isSymbolExport)
        : symbolName(std::move(symbolName)), moduleName(std::move(moduleName)), isSymbolExport(isSymbolExport) {
    }

    AddressEntry AddressEntry::WithKnownAddress(std::string symbolName,
        std::wstring moduleName,
        uintptr_t address,
        bool isSymbolExport) {
        AddressEntry entry(std::move(symbolName), std::move(moduleName), isSymbolExport);
        entry.SetKnownAddress(address);
        return entry;
    }

    AddressEntry AddressEntry::WithKnownOffset(std::string symbolName,
        std::wstring moduleName,
        uintptr_t offset,
        bool isSymbolExport) {
        AddressEntry entry(std::move(symbolName), std::move(moduleName));
        entry.SetKnownOffset(offset);
        return entry;
    }

    AddressEntry AddressEntry::WithScanPattern(std::string symbolName,
        std::wstring moduleName,
        std::string pattern,
        bool isSymbolExport) {
        AddressEntry entry(std::move(symbolName), std::move(moduleName));
        entry.SetScanPattern(pattern);
        return entry;
    }

    // --- Setters ---
    void AddressEntry::SetModuleBase(uintptr_t moduleAddress) {
        this->moduleAddress = moduleAddress;
    }

    void AddressEntry::SetKnownAddress(uintptr_t targetAddress) {
        this->targetAddress = targetAddress;
    }

    void AddressEntry::SetKnownOffset(uintptr_t offset) {
        this->knownOffset = offset;
    }

    void AddressEntry::SetScanPattern(const std::string& pattern) {
        this->scanPattern = pattern;
        this->scanBytes_ = AddressScanner::ParsePattern(pattern);
    }

    // --- Accessors ---
    std::optional<uintptr_t> AddressEntry::Update()
    {
        // Case 2: exported symbol
        if (isSymbolExport) {
            auto scan = AddressScanner::LookupExportAddress(moduleName, symbolName);
            if (scan.has_value()) {
                auto& [moduleBase, sigAddress, offset] = scan.value();
                SetModuleBase(moduleBase);
                SetKnownAddress(sigAddress);
                SetKnownOffset(offset);
                return targetAddress;
            }
            else {
                error("[AddressEntry] Failed to lookup address by symbolName for %s", symbolName.c_str());
            }
        }
        // Case 3: pattern scan
        else if (scanBytes_.has_value()) {
            auto scan = AddressScanner::ModuleSearch(moduleName, symbolName, scanBytes_.value());
            if (scan.has_value()) {
                auto& [moduleBase, sigAddress, offset] = scan.value();
                SetModuleBase(moduleBase);
                SetKnownAddress(sigAddress);
                SetKnownOffset(offset);
                return targetAddress;
            }
            else {
                error("[AddressEntry] Failed to lookup address by pattern scan for %s", symbolName.c_str());
            }
        // Case 1: moduleBase + offset
        } else if (moduleAddress > 0 && knownOffset.value_or(0) > 0) {
            SetKnownAddress(moduleAddress + knownOffset.value());
            return targetAddress;
        }
        // Case 4: moduleName + offset
        else if (!moduleName.empty() && knownOffset.value_or(0) > 0) {
            HMODULE hMod = GetModuleHandleW(moduleName.c_str());
            if (!hMod) {
                error("[AddressScanner] Module %ls not loaded yet.", moduleName.c_str());
                return std::nullopt;
            }
            SetModuleBase((uintptr_t)hMod);
            SetKnownAddress((uintptr_t)hMod + knownOffset.value());
            return targetAddress;
        }

        error("[AddressEntry] Complete failure to find address for symbol %s", symbolName.c_str());
        return std::nullopt;    
    }

    std::optional<uintptr_t> AddressEntry::GetAddress() const {
        if (targetAddress)
            return targetAddress;
        // Case 1: module base + known offset
        else        
        if (moduleAddress > 0 && knownOffset.value_or(0) > 0) {
            return moduleAddress + knownOffset.value();
        }
        // Case 2: exported symbol
        else        
        if (isSymbolExport) {
            auto scan = AddressScanner::LookupExportAddress(moduleName, symbolName);
            if (scan.has_value()) {
                auto& [moduleBase, sigAddress, offset] = scan.value();
                warn("[AddressEntry] Warning: const access against non-updated entry (%s). consider calling entry::Update()", symbolName.c_str());
                return sigAddress;
            }
            else {
                error("[AddressEntry] Failed to lookup address by symbolName for %s", symbolName.c_str());
            }
        }
        // Case 3: pattern scan
        else
        if (scanBytes_.has_value()) {
            auto scan = AddressScanner::ModuleSearch(moduleName, symbolName, scanBytes_.value());
            if (scan.has_value()) {
                auto& [moduleBase, sigAddress, offset] = scan.value();
                warn("[AddressEntry] Warning: const access against non-updated entry (%s). consider calling entry::Update()", symbolName.c_str());
                return sigAddress;
            }
            else {
                error("[AddressEntry] Failed to lookup address by pattern scan for %s", symbolName.c_str());
            }
        }
        // Case 4: moduleName + offset
        else
        if (!moduleName.empty() && knownOffset.value_or(0) > 0) {
            HMODULE hMod = GetModuleHandleW(moduleName.c_str());
            if (!hMod) {
                error("[AddressScanner] Module %ls not loaded yet.", moduleName.c_str());
                return std::nullopt;
            }
            return (uintptr_t)hMod + knownOffset.value();
        }

        error("[AddressEntry] Complete failure to find address for symbol %s", symbolName.c_str());
        return std::nullopt;
    }

    std::optional<uintptr_t> AddressEntry::GetAddress() {
        if (targetAddress > 0)
            return targetAddress;
        else
        // Case 1: module base + known offset
        if (moduleAddress > 0 && knownOffset.value_or(0) > 0) {
            SetKnownAddress(moduleAddress + knownOffset.value());
            return targetAddress;
        }
        else {
            // Case 2: exported symbol
            // Case 3: pattern scan
            // Case 4: moduleName + offset
            auto result = Update();
            if (result.has_value())
                return result.value();
        }

        error("[AddressEntry] Complete failure to find address for symbol %s", symbolName.c_str());
        return std::nullopt;
    }

    // --- Debugging ---
    void AddressEntry::Dump() const {
        debug(" --- %s Dump ---", symbolName.c_str());
        debug(" Module Name   : %ls", moduleName.c_str());
        debug(" Module Base   : 0x%016llx", (moduleAddress));
        debug(" Offset        : 0x%llx", knownOffset.value_or(0));
        debug(" Final Address : 0x%016llx\n", GetAddress());
    }

    bool AddressEntry::Verify() const
    {
        uintptr_t newAddress{};

        // Case 1: module base + known offset
        if (moduleAddress > 0 && knownOffset.value_or(0) > 0) {
            uintptr_t newAddress = moduleAddress + knownOffset.value();
        }
        // Case 2: exported symbol
        else
        if (isSymbolExport) {
            auto lookup = AddressScanner::LookupExportAddress(moduleName, symbolName);
            if (!lookup.has_value()) {
                error("[AddressEntry] Failed to find exported address for %s!", symbolName.c_str());
                return false;
            }
            const auto& [moduleBase, signatureAddress, offset] = lookup.value();
            newAddress = signatureAddress;
        }

        // Case 3: pattern scan
        else
        if (scanBytes_.has_value()) {
            auto search = AddressScanner::ModuleSearch(moduleName, symbolName, scanBytes_.value());
            if (!search.has_value()) {
                error("[AddressEntry] Failed to search module for pattern matching symbol %s!", symbolName.c_str());
                return false;
            }
            const auto& [moduleBase, signatureAddress, offset] = search.value();
            newAddress = signatureAddress;
        }

        if (newAddress) {
            if (newAddress == targetAddress)
                return true;
            else
                return false;
        }

        if (targetAddress)
            return true;

        return false;
    }
}
