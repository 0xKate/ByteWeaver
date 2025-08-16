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
    uintptr_t AddressEntry::GetAddress() {
        // Already know the address
        if (targetAddress)
            return targetAddress;

        // Already know the offset
        if (moduleAddress && knownOffset.has_value()) {
            SetKnownAddress(moduleAddress + knownOffset.value());
            return targetAddress;
        }

        // Scan for the epxorted symbol in the module
        if (isSymbolExport) {
            auto address = AddressScanner::LookupExportAddress(moduleName, symbolName);
            if (address.has_value()) {
                SetKnownAddress(address.value());
                return targetAddress;
            }
            else {
                error("[AddressEntry] Failed to lookup address by symbolName for %s", symbolName.c_str());
            }
        }

        // If we can scan, do it once, cache the offset, and address.
        if (scanPattern.has_value()) {
            auto scan = AddressScanner::ModuleSearch(symbolName, moduleName, scanPattern.value());            
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
            
        }

        error("[AddressEntry] Complete failure to find address for symbol %s", symbolName.c_str());
        return 0x0;
    }

    // --- Debugging ---
    void AddressEntry::Dump() {
        debug(" --- %s Dump ---", symbolName.c_str());
        debug(" Module Name   : %ls", moduleName.c_str());
        debug(" Module Base   : 0x%016llx", (moduleAddress));
        debug(" Offset        : 0x%llx", knownOffset.value_or(0));
        debug(" Final Address : 0x%016llx\n", GetAddress());
    }
}
