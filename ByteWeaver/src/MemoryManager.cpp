// Copyright(C) 2025 0xKate - MIT License

#include "ByteWeaverPCH.h"
#include "MemoryManager.h"

#include <utility>

#include "WinPatch.h"
#include "WinDetour.h"

namespace ByteWeaver {

    std::map<std::string, std::shared_ptr<MemoryModification>> MemoryManager::Mods;
    std::shared_mutex MemoryManager::ModsMutex;

    uintptr_t MemoryManager::GetBaseAddress() {
        HMODULE hModule = GetModuleHandle(nullptr);
        return reinterpret_cast<uintptr_t>(hModule);
    }

    // --- class MemoryModification
    bool MemoryManager::ModExists(const std::string& key, std::shared_ptr<MemoryModification>* hOutMod) {
        std::shared_lock lock(ModsMutex);
        if (const auto it = Mods.find(key); it != Mods.end()) {
            if (hOutMod)
                *hOutMod = it->second;
            else
                Error("[MemoryManager] Mod with key '%s' already exists!", key.c_str());
            return true;
        }
        return false;
    }

    bool MemoryManager::AddMod(const std::string& key, std::shared_ptr<MemoryModification> hMod, const uint16_t groupID) {
        if (!ModExists(key)) {
            std::unique_lock lock(ModsMutex);
            hMod->Key = key;
            hMod->GroupID = groupID;
            Mods.emplace(key, hMod);
            return true;
        }
        return false;
    }

    bool MemoryManager::EraseMod(const std::string& key) {
        std::unique_lock lock(ModsMutex);
        if (const auto it = Mods.find(key); it != Mods.end()) {
            Mods.erase(it);
            return true;
        }
        Error("[MemoryManager] (EraseMod) Mod with key '%s' does not exist!", key.c_str());
        return false;
    }

    auto MemoryManager::GetMod(const std::string& key) -> std::shared_ptr<MemoryModification> {
        std::shared_lock lock(ModsMutex);
        if (const auto it = Mods.find(key); it != Mods.end()) {
            return it->second;
        }
        Error("[MemoryManager] (GetMod) Mod with key '%s' does not exist!", key.c_str());
        return nullptr;
    }

    bool MemoryManager::ApplyMod(const std::string& key) {
        std::shared_ptr<MemoryModification> hMod;
        if (ModExists(key, &hMod)) {
            hMod->Apply();
        }
        return false;
    }

    bool MemoryManager::RestoreMod(const std::string& key) {
        std::shared_ptr<MemoryModification> hMod;
        if (ModExists(key, &hMod)) {
            hMod->Restore();
        }
        return false;
    }

    bool MemoryManager::RestoreAndEraseMod(const std::string& key) {
        const bool a = RestoreMod(key);
        const bool b = EraseMod(key);
        return a & b;
    }

    bool MemoryManager::CreatePatch(const std::string& key, uintptr_t patchAddress, std::vector<uint8_t> patchBytes, const uint16_t groupID) {
        if (!ModExists(key)) {
            const auto patch = std::make_shared<Patch>(patchAddress, patchBytes);
            AddMod(key, patch, groupID);
            return true;
        }
        return false;
    }

    bool MemoryManager::CreateDetour(const std::string& key, uintptr_t targetAddress, PVOID* originalFunction, PVOID detourFunction, const uint16_t groupID) {
        if (!ModExists(key)) {
            const auto detour = std::make_shared<Detour>(targetAddress, originalFunction, detourFunction);
            AddMod(key, detour, groupID);
            return true;
        }
        return false;
    }

    auto MemoryManager::GetAllMods() -> std::vector<std::shared_ptr<MemoryModification>>
    {
        std::shared_lock lock(ModsMutex);

        std::vector<std::shared_ptr<MemoryModification>> allMods;
        allMods.reserve(Mods.size());

        for (const auto& hMod : Mods | std::views::values) {
            allMods.push_back(hMod);
        }

        return allMods;
    }

    bool MemoryManager::ApplyAllMods() {
        std::shared_lock lock(ModsMutex);
        return std::ranges::all_of(Mods | std::views::values,
            [](const auto& hMod) -> bool {
                return hMod->Apply();
            });
    }

    bool MemoryManager::RestoreAllMods()
    {
        std::shared_lock lock(ModsMutex);

        return std::ranges::all_of(Mods | std::views::values,
            [](const auto& hMod) { return hMod->Restore(); });
    }

    void MemoryManager::RestoreAndEraseAllMods()
    {
        std::unique_lock lock(ModsMutex);

        std::erase_if(Mods, [](const auto& pair) {
            pair.second->Restore();
            return true;
        });
    }

    void MemoryManager::EraseAllMods()
    {
        std::unique_lock lock(ModsMutex);
        Mods.clear();
    }

    auto MemoryManager::GetModsByGroupID(const uint16_t groupID)-> std::vector<std::shared_ptr<MemoryModification>>
    {
        std::shared_lock lock(ModsMutex);

        std::vector<std::shared_ptr<MemoryModification>> groupIdMods;
        groupIdMods.reserve(Mods.size());

        for (const auto& hMod : Mods | std::views::values) {
            if (hMod->GroupID == groupID) {
                groupIdMods.push_back(hMod);
            }
        }

        return groupIdMods;
    }

    // Only applies enabled mods
    bool MemoryManager::ApplyByGroupID(const uint16_t groupID)
    {
        std::shared_lock lock(ModsMutex);
        return std::ranges::all_of(Mods | std::views::values,
            [groupID](const auto& hMod) -> bool {
                if (hMod->GroupID == groupID)
                    return hMod->Apply();
                return true;
            });
    }

    bool MemoryManager::RestoreByGroupID(const uint16_t groupID)
    {
        std::shared_lock lock(ModsMutex);
        return std::ranges::all_of(Mods | std::views::values,
            [groupID](const auto& hMod) -> bool {
                if (hMod->GroupID == groupID)
                    return hMod->Restore();
                return true;
            });
    }

    void MemoryManager::EraseByGroupID(const uint16_t groupID)
    {
        std::unique_lock lock(ModsMutex);
        std::erase_if(Mods, [groupID](const auto& pair) {
            if (pair.second->GroupID == groupID) {
                return true; // Tells erase_if to erase this element
            }
            return false;
        });

    }

    void MemoryManager::RestoreAndEraseByGroupID(const uint16_t groupID)
    {
        std::unique_lock lock(ModsMutex);
        std::erase_if(Mods, [groupID](const auto& pair) {
            if (pair.second->GroupID == groupID) {
                pair.second->Restore();
                return true; // Tells erase_if to erase this element
            }
            return false;
        });
    }

    auto MemoryManager::GetModsByType(const ModType modType)-> std::vector<std::shared_ptr<MemoryModification>>
    {
        std::shared_lock lock(ModsMutex);

        std::vector<std::shared_ptr<MemoryModification>> typeMods;
        typeMods.reserve(Mods.size());

        for (const auto& hMod : Mods | std::views::values) {
            if (hMod->Type == modType) {
                typeMods.push_back(hMod);
            }
        }

        return typeMods;
    }

    bool MemoryManager::ApplyByType(const ModType modType)
    {
        std::shared_lock lock(ModsMutex);

        return std::ranges::all_of(Mods | std::views::values,
            [modType](const auto& hMod) -> bool {
                if (hMod->Type == modType && hMod)
                    return hMod->Apply();
                return true;
            });
    }

    bool MemoryManager::RestoreByType(const ModType modType)
    {
        std::shared_lock lock(ModsMutex);

        return std::ranges::all_of(Mods | std::views::values,
            [modType](const auto& hMod) -> bool {
                if (hMod->Type == modType)
                    return hMod->Restore();
                return true;
            });
    }

    void MemoryManager::EraseByType(const ModType modType)
    {
        std::unique_lock lock(ModsMutex);

        std::erase_if(Mods, [modType](const auto& pair) {
            if (pair.second->Type == modType) {
                return true; // Tells erase_if to erase this element
            }
            return false;
        });

    }

    void MemoryManager::RestoreAndEraseByType(const ModType modType)
    {
        std::unique_lock lock(ModsMutex);

        std::erase_if(Mods, [modType](const auto& pair) {
            if (pair.second->Type == modType) {
                pair.second->Restore();
                return true; // Tells erase_if to erase this element
            }
            return false;
        });
    }

    // --- START Deprecated but backwards compatible

    [[deprecated("Use AddMod(key, mod) or consider using CreatePatch() instead!")]]
    bool MemoryManager::AddPatch(const std::string& key, const std::shared_ptr<Patch>& hPatch, const uint16_t groupID) {
        return AddMod(key, hPatch, groupID);
    }

    [[deprecated("Use AddMod(key, mod) or consider using CreatePatch() instead!")]]
    bool MemoryManager::AddPatch(const std::string& key, Patch* patch, const uint16_t groupID) {
        const auto hPatch = std::shared_ptr<Patch>(patch);
        return AddMod(key, hPatch, groupID);
    }

    [[deprecated("Use MemoryManager::EraseMod(key) instead")]]
    bool MemoryManager::ErasePatch(const std::string& key) {
        return EraseMod(key);
    }

    [[deprecated("Use MemoryManager::RestoreAndEraseMod(key) instead")]]
    bool MemoryManager::RestoreAndErasePatch(const std::string& key) {
        return RestoreAndEraseMod(key);
    }

    [[deprecated("Use MemoryManager::ApplyByType(ModType::Patch) instead")]]
    bool MemoryManager::ApplyPatches() {
        return ApplyByType(ModType::Patch);
    }

    [[deprecated("Use MemoryManager::RestoreByType(ModType::Patch) instead")]]
    bool MemoryManager::RestorePatches() {
        return RestoreByType(ModType::Patch);
    }

    [[deprecated("Use AddMod(key, mod) or consider using CreateDetour() instead!")]]
    bool MemoryManager::AddDetour(const std::string& key, const std::shared_ptr<Detour>& hDetour, const uint16_t groupID) {
        return AddMod(key, hDetour, groupID);
    }

    [[deprecated("Use AddMod(key, mod) or consider using CreateDetour() instead!")]]
    bool MemoryManager::AddDetour(const std::string& key, Detour* detour, const uint16_t groupID) {
        const auto hDetour = std::shared_ptr<Detour>(detour);
        return AddMod(key, hDetour, groupID);
    }

    [[deprecated("Use MemoryManager::EraseMod(key) instead")]]
    bool MemoryManager::EraseDetour(const std::string& key) {
        return EraseMod(key);
    }

    [[deprecated("Use MemoryManager::RestoreAndEraseMod(key) instead")]]
    bool MemoryManager::RestoreAndEraseDetour(const std::string& key) {
        return RestoreAndEraseMod(key);
    }

    [[deprecated("Use MemoryManager::ApplyByType(ModType::Detour) instead")]]
    bool MemoryManager::ApplyDetours() {
        return ApplyByType(ModType::Detour);
    }

    [[deprecated("Use MemoryManager::RestoreByType(ModType::Detour) instead")]]
    bool MemoryManager::RestoreDetours() {
        return RestoreByType(ModType::Detour);
    }

    [[deprecated("Use MemoryManager::ApplyAllMods() instead")]]
    bool MemoryManager::ApplyAll() {
        const bool a = ApplyDetours();
        const bool b = ApplyPatches();
        Debug("[MemoryManager] Applied all detours and enabled patches!");
        return a & b;
    }

    [[deprecated("Use MemoryManager::RestoreAllMods() instead")]]
    bool MemoryManager::RestoreAll() {
        const bool a = RestorePatches();
        const bool b = RestoreDetours();
        Debug("[MemoryManager] Restored all detours and patches.");
        return a & b;
    }

    [[deprecated("Use MemoryManager::EraseAllMods() instead")]]
    void MemoryManager::ClearAll() {
        std::unique_lock lock(ModsMutex);
        Mods.clear();
    }

    [[deprecated("Use MemoryManager::ApplyMod() instead")]]
    void MemoryManager::ApplyByKey(const std::string& key) {
        ApplyMod(key);
    }

    [[deprecated("Use MemoryManager::RestoreMod() instead")]]
    void MemoryManager::RestoreByKey(const std::string& key) {
        RestoreMod(key);
    }

    // --- END Deprecated but backwards compatible

    // --- Memory Modifying Functions

    bool MemoryManager::IsLocationModified(const uintptr_t address, const size_t length, std::vector<std::string>* detectedKeys) {
        const uintptr_t endAddress = address + length;

        for (const auto& [key, mod] : Mods) {
            if (mod->IsModified) {
                if (const uintptr_t modEnd = mod->TargetAddress + mod->Size; address < modEnd && endAddress > mod->TargetAddress) {
                    detectedKeys->push_back(key);
                }
            }
        }

        if (!detectedKeys->empty())
            return true;

        return false;
    }

    bool MemoryManager::IsAddressValid(const uintptr_t address) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(GetCurrentProcess(), reinterpret_cast<void*>(address), &mbi, sizeof(mbi))) {
            return mbi.State == MEM_COMMIT &&
                mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                    PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE);
        }
        return false;
    }

    bool MemoryManager::IsMemoryRangeValid(const uintptr_t address, const size_t length) {
        uintptr_t currentAddress = address;
        const uintptr_t endAddress = address + length;

        while (currentAddress < endAddress) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(GetCurrentProcess(), reinterpret_cast<void*>(currentAddress), &mbi, sizeof(mbi))) {
                if (mbi.State != MEM_COMMIT ||
                    !(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
                {
                    return false;
                }
                currentAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            }
            else {
                return false;
            }
        }
        return true;
    }

    bool MemoryManager::IsAddressReadable(const uintptr_t address)
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(GetCurrentProcess(), reinterpret_cast<void*>(address), &mbi, sizeof(mbi)))
        {
            return mbi.State == MEM_COMMIT &&
                mbi.Protect & PAGE_READONLY;
        }
        return false;
    }

    uintptr_t MemoryManager::ReadAddress(const uintptr_t address) {
        if (address == NULL || !IsAddressValid(address))
            return NULL;

        __try {
            return *reinterpret_cast<uintptr_t*>(address);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Error("Exception caught: access violation while attempting to read address: %lld", address);
            return NULL;
        }
    }

    std::string MemoryManager::ReadStringSafe(const uintptr_t address, const size_t maxLength) {
        const char* buffer = nullptr;

        buffer = reinterpret_cast<const char*>(address);

        if (buffer != nullptr)
        {
            size_t length = 0;
            while (length < maxLength && buffer[length] != '\0') {
                ++length;
            }
            return { buffer, length };
        }

        return buffer;
    }

    std::string MemoryManager::ReadString(const uintptr_t address) {
        return std::string{ reinterpret_cast<const char*>(address) };
    }

    uintptr_t MemoryManager::GetModuleBaseAddress(const wchar_t* moduleName)
    {
        if (HMODULE hMod = GetModuleHandleW(moduleName); !hMod) {
            Error("%s not loaded yet.", moduleName);
            return 0;
        }
        else {
            return reinterpret_cast<uintptr_t>(hMod);
        }
    }

    uintptr_t MemoryManager::GetModuleBaseAddressFast(const void* p)
    {
        PVOID moduleBase = nullptr;
        if (RtlPcToFileHeader(const_cast<void*>(p), &moduleBase))
            return reinterpret_cast<uintptr_t>(moduleBase);
        return 0;
    }

    uintptr_t MemoryManager::GetModuleBaseAddressFast(const uintptr_t address)
    {
        return GetModuleBaseAddressFast(reinterpret_cast<void*>(address));
    }

    std::pair<uintptr_t, uintptr_t> MemoryManager::GetModuleBounds(const uintptr_t address)
    {
        uintptr_t moduleBase = GetModuleBaseAddressFast(address);
        if (!moduleBase) {
            Error("[GetModuleBounds] Address " ADDR_FMT " is not inside a module!", address);
            return { 0,0 };
        }

        const auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(moduleBase);
        const auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(moduleBase + dos->e_lfanew);

        return { moduleBase , moduleBase + nt->OptionalHeader.SizeOfImage };
    }

    fs::path MemoryManager::GetModulePath(const uintptr_t moduleBase)
    {
        wchar_t buff[MAX_PATH];
        const DWORD n = GetModuleFileNameW(reinterpret_cast<HMODULE>(GetModuleBaseAddressFast(moduleBase)),
            buff,
            std::size(buff));
        if (n == 0)
            return {};

        return {buff};
    }

#ifdef _WIN64
    std::pair<uintptr_t, uintptr_t> MemoryManager::GetFunctionBounds(const uintptr_t address)
    {
        if (!address) return { 0, 0 };

        DWORD64 imageBase = 0;
        if (const auto* rf = RtlLookupFunctionEntry(address, &imageBase, nullptr)) {
            const auto start = imageBase + rf->BeginAddress;
            const auto end = imageBase + rf->EndAddress;
            return { start, end };
        }
        return { 0, 0 };
    }
#endif

    fs::path MemoryManager::ReadWindowsPath(const char* address) {
        std::string safe(address);

        constexpr std::string_view invalidChars = R"delim(<>:"/\|?*)delim";

        std::ranges::transform(safe, safe.begin(), [invalidChars](const char ch) {
            if (ch < 0x20 || invalidChars.find(ch) != std::string_view::npos)
                return '_';
            return ch;
        });

        return safe;
    }

    fs::path MemoryManager::ReadWindowsPath(const uintptr_t address) {
        return ReadWindowsPath(reinterpret_cast<const char*>(address));
    }

    void MemoryManager::WriteBufferToFile(const uintptr_t address, const size_t length, const fs::path& outPath) {
        return WriteBufferToFile(reinterpret_cast<const char*>(address), length, outPath);
    }

    void MemoryManager::WriteBufferToFile(const char* buffer, const size_t length, const fs::path& outPath) {
        std::ofstream outFile(outPath, std::ios::binary);
        if (!outFile) {
            throw std::runtime_error("Failed to open file: " + outPath.string());
        }

        outFile.write(buffer, length);
        outFile.close();
    }

    std::vector<uint8_t> MemoryManager::ReadBytesSafe(const uintptr_t address, const size_t size) {
        if (!address || !size)
            return {};

        if (!IsMemoryRangeValid(address, size))
            return {};

        std::vector<uint8_t> buffer(size);
        std::memcpy(buffer.data(), reinterpret_cast<const void*>(address), size);
        return buffer;
    }

    std::string MemoryManager::BytesToHex(const std::vector<uint8_t>& data) {
        if (data.empty()) return "";

        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (const uint8_t b : data) {
            oss << std::setw(2) << static_cast<unsigned>(b);
        }
        return oss.str();
    }

}
