// Copyright(C) 2025 0xKate - MIT License

#include "ByteWeaver.h"
#include "AddressEntry.h"
#include "AddressScanner.h"

namespace ByteWeaver {

    // --- Constructors ---
    AddressEntry::AddressEntry(std::string symbolName, std::wstring moduleName)
        : SymbolName(std::move(symbolName)), ModuleName(std::move(moduleName)) {
    }

    AddressEntry AddressEntry::WithKnownAddress(std::string symbolName,
        std::wstring moduleName,
        const uintptr_t address) {
        AddressEntry entry(std::move(symbolName), std::move(moduleName));
        entry.SetKnownAddress(address);
        entry.IsSymbolExport = false;
        return entry;
    }

    AddressEntry AddressEntry::WithKnownOffset(std::string symbolName,
        std::wstring moduleName,
        const uintptr_t offset) {
        AddressEntry entry(std::move(symbolName), std::move(moduleName));
        entry.SetKnownOffset(offset);
        entry.IsSymbolExport = false;
        return entry;
    }

    AddressEntry AddressEntry::WithScanPattern(std::string symbolName,
        std::wstring moduleName,
        const std::string& pattern) {
        AddressEntry entry(std::move(symbolName), std::move(moduleName));
        entry.SetScanPattern(pattern);
        entry.IsSymbolExport = false;
        return entry;
    }

    // --- Setters ---
    void AddressEntry::SetModuleBase(const uintptr_t moduleAddress) {
        this->ModuleAddress = moduleAddress;
    }

    void AddressEntry::SetKnownAddress(const uintptr_t targetAddress) {
        this->TargetAddress = targetAddress;
    }

    void AddressEntry::SetKnownOffset(uintptr_t offset) {
        this->KnownOffset = offset;
    }

    void AddressEntry::SetScanPattern(const std::string& pattern) {
        this->ScanPattern = pattern;
        this->_ScanBytes = AddressScanner::ParsePattern(pattern);
    }

    // --- Accessors ---
    std::optional<uintptr_t> AddressEntry::Update()
    {
        // Case 2: exported symbol
        if (IsSymbolExport) {
            if (auto scan = AddressScanner::LookupExportAddress(ModuleName, SymbolName); scan.has_value()) {
                auto& [moduleBase, sigAddress, offset] = scan.value();
                SetModuleBase(moduleBase);
                SetKnownAddress(sigAddress);
                SetKnownOffset(offset);
                return TargetAddress;
            }
            Error("[AddressEntry] Failed to lookup address by symbolName for %s", SymbolName.c_str());
        }
        // Case 3: pattern scan
        else if (_ScanBytes.has_value()) {
            if (auto scan = AddressScanner::ModuleSearch(ModuleName, SymbolName, _ScanBytes.value()); scan.has_value()) {
                auto& [moduleBase, sigAddress, offset] = scan.value();
                SetModuleBase(moduleBase);
                SetKnownAddress(sigAddress);
                SetKnownOffset(offset);
                return TargetAddress;
            }
            Error("[AddressEntry] Failed to lookup address by pattern scan for %s", SymbolName.c_str());
            // Case 1: moduleBase + offset
        } else if (ModuleAddress > 0 && KnownOffset.value_or(0) > 0) {
            SetKnownAddress(ModuleAddress + KnownOffset.value());
            return TargetAddress;
        }
        // Case 4: moduleName + offset
        else if (!ModuleName.empty() && KnownOffset.value_or(0) > 0) {
            HMODULE hMod = GetModuleHandleW(ModuleName.c_str());
            if (!hMod) {
                Error("[AddressScanner] Module %ls not loaded yet.", ModuleName.c_str());
                return std::nullopt;
            }
            SetModuleBase(reinterpret_cast<uintptr_t>(hMod));
            SetKnownAddress(reinterpret_cast<uintptr_t>(hMod) + KnownOffset.value());
            return TargetAddress;
        }

        Error("[AddressEntry] Complete failure to find address for symbol %s", SymbolName.c_str());
        return std::nullopt;    
    }

    std::optional<uintptr_t> AddressEntry::GetAddress() const {
        if (TargetAddress)
            return TargetAddress;
        // Case 1: module base + known offset
        if (ModuleAddress > 0 && KnownOffset.value_or(0) > 0) {
            return ModuleAddress + KnownOffset.value();
        }
        // Case 2: exported symbol
        if (IsSymbolExport) {
            if (auto scan = AddressScanner::LookupExportAddress(ModuleName, SymbolName); scan.has_value()) {
                auto& [moduleBase, sigAddress, offset] = scan.value();
                Warn("[AddressEntry] Warning: const access against non-updated entry (%s). consider calling entry::Update()", SymbolName.c_str());
                return sigAddress;
            }
            Error("[AddressEntry] Failed to lookup address by symbolName for %s", SymbolName.c_str());
        }
        // Case 3: pattern scan
        else
            if (_ScanBytes.has_value()) {
                if (auto scan = AddressScanner::ModuleSearch(ModuleName, SymbolName, _ScanBytes.value()); scan.has_value()) {
                    auto& [moduleBase, sigAddress, offset] = scan.value();
                    Warn("[AddressEntry] Warning: const access against non-updated entry (%s). consider calling entry::Update()", SymbolName.c_str());
                    return sigAddress;
                }
                Error("[AddressEntry] Failed to lookup address by pattern scan for %s", SymbolName.c_str());
            }
            // Case 4: moduleName + offset
            else
                if (!ModuleName.empty() && KnownOffset.value_or(0) > 0) {
                    HMODULE hMod = GetModuleHandleW(ModuleName.c_str());
                    if (!hMod) {
                        Error("[AddressScanner] Module %ls not loaded yet.", ModuleName.c_str());
                        return std::nullopt;
                    }
                    return reinterpret_cast<uintptr_t>(hMod) + KnownOffset.value();
                }

        Error("[AddressEntry] Complete failure to find address for symbol %s", SymbolName.c_str());
        return std::nullopt;
    }

    std::optional<uintptr_t> AddressEntry::GetAddress() {
        if (TargetAddress > 0)
            return TargetAddress;

        // Case 1: module base + known offset
        if (ModuleAddress > 0 && KnownOffset.value_or(0) > 0) {
            SetKnownAddress(ModuleAddress + KnownOffset.value());
            return TargetAddress;
        }
        // Case 2: exported symbol
        // Case 3: pattern scan
        // Case 4: moduleName + offset
        if (auto result = Update(); result.has_value())
            return result.value();

        Error("[AddressEntry] Complete failure to find address for symbol %s", SymbolName.c_str());
        return std::nullopt;
    }

    // --- Debugging ---
    void AddressEntry::Dump() const {
        Debug("[AddressEntry] --- %s Dump ---", SymbolName.c_str());
        Debug("[AddressEntry]  - Module Name   : %ls", ModuleName.c_str());
        Debug("[AddressEntry]  - Module Base   : " ADDR_FMT, ModuleAddress);
        Debug("[AddressEntry]  - Offset        : 0x%llx", KnownOffset.value_or(0));
        Debug("[AddressEntry]  - Final Address : " ADDR_FMT, GetAddress());
    }

    bool AddressEntry::Verify() const
    {
        uintptr_t newAddress{};

        // Case 1: module base + known offset
        if (ModuleAddress > 0 && KnownOffset.value_or(0) > 0) {
            return true;
        }
        // Case 2: exported symbol
        if (IsSymbolExport) {
            auto lookup = AddressScanner::LookupExportAddress(ModuleName, SymbolName);
            if (!lookup.has_value()) {
                Error("[AddressEntry] Failed to find exported address for %s!", SymbolName.c_str());
                return false;
            }
            const auto& [moduleBase, signatureAddress, offset] = lookup.value();
            newAddress = signatureAddress;
        }

        // Case 3: pattern scan
        else
            if (_ScanBytes.has_value()) {
                auto search = AddressScanner::ModuleSearch(ModuleName, SymbolName, _ScanBytes.value());
                if (!search.has_value()) {
                    Error("[AddressEntry] Failed to search module for pattern matching symbol %s!", SymbolName.c_str());
                    return false;
                }
                const auto& [moduleBase, signatureAddress, offset] = search.value();
                newAddress = signatureAddress;
            }

        if (newAddress) {
            if (newAddress == TargetAddress)
                return true;
            return false;
        }

        if (TargetAddress)
            return true;

        return false;
    }
}
