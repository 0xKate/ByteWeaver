// Copyright(C) 2025 0xKate - MIT License

#include <cassert>
#include <MemoryManager.h>

#include <WinDetour.h>
#include <WinPatch.h>

namespace ByteWeaver {

    std::map<std::string, std::shared_ptr<MemoryModification>> MemoryManager::Mods;
    std::shared_mutex MemoryManager::ModsMutex;

    uintptr_t MemoryManager::GetBaseAddress() {
        HMODULE hModule = GetModuleHandle(nullptr);
        return reinterpret_cast<uintptr_t>(hModule);
    }

    bool MemoryManager::ModExists(const std::string& key, std::shared_ptr<MemoryModification>* hOutMod) {
        std::shared_lock lock(ModsMutex);
        if (const auto it = Mods.find(key); it != Mods.end()) {
            if (hOutMod)
                *hOutMod = it->second;
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

    bool MemoryManager::AddMod(const std::string& key, Patch* patch, const uint16_t groupID) {
        return AddMod(key, std::shared_ptr<MemoryModification>(patch), groupID);
    }

    bool MemoryManager::AddMod(const std::string& key, Detour* detour, const uint16_t groupID) {
        return AddMod(key, std::shared_ptr<MemoryModification>(detour), groupID);
    }

    bool MemoryManager::AddMod(const std::string& key, const std::shared_ptr<Patch>& hPatch, const uint16_t groupID) {
        return AddMod(key, static_cast<std::shared_ptr<MemoryModification>>(hPatch), groupID);
    }

    bool MemoryManager::AddMod(const std::string& key, const std::shared_ptr<Detour>& hDetour, const uint16_t groupID) {
        return AddMod(key, static_cast<std::shared_ptr<MemoryModification>>(hDetour), groupID);
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

    std::shared_ptr<Patch> MemoryManager::CreatePatch(const std::string& key, uintptr_t patchAddress, const std::vector<uint8_t>& patchBytes, const uint16_t groupID) {
        std::shared_ptr<MemoryModification> existingMod;
        if (!ModExists(key, &existingMod)) {
            auto patch = std::make_shared<Patch>(patchAddress, patchBytes);
            AddMod(key, patch, groupID);
            return patch;
        }

        Warn("Attempted to create a Patch with already existing key and returned existing Patch instead.");
        return std::dynamic_pointer_cast<Patch>(existingMod); // Will return nullptr if the existing mod by 'Key' was not actually a patch.
    }

    std::shared_ptr<Detour> MemoryManager::CreateDetour(const std::string& key, uintptr_t targetAddress, PVOID* originalFunction, PVOID detourFunction, const uint16_t groupID) {
        std::shared_ptr<MemoryModification> existingMod = nullptr;
        if (!ModExists(key, &existingMod)) {
            auto detour = std::make_shared<Detour>(targetAddress, originalFunction, detourFunction);
            AddMod(key, detour, groupID);
            return detour;
        }

        Warn("Attempted to create a Detour with already existing key and returned existing Detour instead.");
        return std::dynamic_pointer_cast<Detour>(existingMod); // Will return nullptr if the existing mod by 'Key' was not actually a detour.
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

    // --- Memory Modifying Functions

    bool MemoryManager::DoRangesIntersect(const uintptr_t addr1, const size_t size1,
                      const uintptr_t addr2, const size_t size2) {
        // Handle overflow: check if end address would wrap around
        const uintptr_t end1 = addr1 + size1;
        const uintptr_t end2 = addr2 + size2;

        // Check for overflow in either range
        if (end1 < addr1 || end2 < addr2) {
            // If either range wraps around, they intersect unless one is entirely
            // before the other's start
            return true; // Conservative approach for overflow cases
        }

        // Standard intersection check for [addr1, end1) and [addr2, end2)
        return addr1 < end2 && addr2 < end1;
    }

    // ReSharper disable once CppTooWideScopeInitStatement // disabled for compiler optimization
    bool MemoryManager::IsLocationModifiedFast(const uintptr_t address, const size_t length, std::vector<const char*>& detectedKeys) {
        detectedKeys.reserve(Mods.size()); // prevents reallocations

        const uintptr_t endAddress = address + length;

        // loop without any auto-unpacking, just pointers to avoid structured bindings
        for (auto it = Mods.begin(); it != Mods.end(); ++it) {
            const MemoryModification* mm = it->second.get(); // direct pointer access
            const uintptr_t modStart = mm->TargetAddress;

            const uintptr_t modEnd   = modStart + mm->Size;

            // branchless style (compiler may auto-vectorize)
            if (mm->IsModified & (address < modEnd) & (endAddress > modStart)) {
                detectedKeys.push_back(it->first.c_str()); // use string pointer to avoid copies
            }
        }

        return !detectedKeys.empty();
    }

    bool MemoryManager::IsLocationModified(const uintptr_t address, const size_t length, std::vector<std::string>* detectedKeys) {
        const uintptr_t endAddress = address + length;

        if (endAddress < address) {
            Warn("[MemoryManager] (IsLocationModified) Integer overflow detected in input range!");
            assert(endAddress >= address && "address range overflow");
        }

        for (const auto& [key, mod] : Mods) {
            if (mod->IsModified) {
                if (const uintptr_t modEnd = mod->TargetAddress + mod->Size; address < modEnd && endAddress > mod->TargetAddress) {
                    detectedKeys->push_back(key);
                }
            }
        }

        return !detectedKeys->empty();
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
