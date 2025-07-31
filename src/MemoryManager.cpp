// Copyright(C) 2025 0xKate - MIT License

#include "ByteWeaver.h"
#include "MemoryManager.h"
#include "WinPatch.h"
#include "WinDetour.h"

namespace ByteWeaver {
    std::map<std::string, std::shared_ptr<Patch>> MemoryManager::Patches;
    std::map<std::string, std::shared_ptr<Detour>> MemoryManager::Detours;

    uintptr_t MemoryManager::GetBaseAddress() {
        HMODULE hModule = GetModuleHandle(nullptr);
        return reinterpret_cast<uintptr_t>(hModule);
    }

    void MemoryManager::AddPatch(std::string key, std::shared_ptr<Patch> hPatch) {
        auto it = Patches.find(key);
        if (it != Patches.end()) {
            warn("Patch with key '%s' already exists and will be replaced.", key.c_str());
            RestoreAndErasePatch(key);
        }
        Patches[key] = hPatch;
    }

    void MemoryManager::AddPatch(std::string key, Patch* hPatch) {
        AddPatch(key, std::shared_ptr<Patch>(hPatch));
    }

    void MemoryManager::ErasePatch(std::string key) {
        auto it = Patches.find(key);
        if (it != Patches.end()) {
            Patches.erase(it);
        }
    }

    void MemoryManager::RestoreAndErasePatch(std::string key) {
        auto it = Patches.find(key);
        if (it != Patches.end()) {
            it->second->Restore();
            Patches.erase(it);
        }
    }

    void MemoryManager::AddDetour(std::string key, std::shared_ptr<Detour> hDetour) {
        auto it = Detours.find(key);
        if (it != Detours.end()) {
            warn("Detour with key '%s' already exists and will be replaced.", key.c_str());
            RestoreAndEraseDetour(key);
        }
        Detours[key] = hDetour;
    }

    void MemoryManager::AddDetour(std::string key, Detour* hDetour) {
        AddDetour(key, std::shared_ptr<Detour>(hDetour));
    }

    void MemoryManager::EraseDetour(std::string key) {
        auto it = Detours.find(key);
        if (it != Detours.end()) {
            Detours.erase(it);
        }
    }

    void MemoryManager::RestoreAndEraseDetour(std::string key) {
        auto it = Detours.find(key);
        if (it != Detours.end()) {
            it->second->Restore();
            Detours.erase(it);
        }
    }

    void MemoryManager::ApplyPatches() {
        for (auto& patchEntry : Patches) {
            std::shared_ptr<Patch> patch = patchEntry.second;
            if (patch && patch->isEnabled) {
                patch->Apply();
            }
        }
    }

    void MemoryManager::RestorePatches() {
        for (const auto& patchEntry : Patches) {
            std::shared_ptr<Patch> patch = patchEntry.second;
            if (patch && patch->isPatched) {
                patch->Restore();
            }
        }
    }

    void MemoryManager::ApplyDetours() {
        for (const auto& detourEntry : Detours) {
            std::shared_ptr<Detour> detour = detourEntry.second;
            if (detour != nullptr) {
                detour->Apply();
            }
        }
    }

    void MemoryManager::RestoreDetours() {
        for (const auto& detourEntry : Detours) {
            std::shared_ptr<Detour> detour = detourEntry.second;
            if (detour != nullptr) {
                detour->Restore();
            }
        }
    }

    void MemoryManager::ApplyByKey(std::string key) {
        auto itDetour = Detours.find(key);
        if (itDetour != Detours.end())
            itDetour->second->Apply();

        auto itPatch = Patches.find(key);
        if (itPatch != Patches.end())
            itPatch->second->Apply();
    }

    void MemoryManager::RestoreByKey(std::string key) {
        auto itPatch = Patches.find(key);
        if (itPatch != Patches.end())
            itPatch->second->Restore();

        auto itDetour = Detours.find(key);
        if (itDetour != Detours.end())
            itDetour->second->Restore();
    }

    void MemoryManager::ApplyAll() {
        ApplyDetours();
        ApplyPatches();
        debug("[MemoryManager] Applied all detours and enabled patches!");
    }

    void MemoryManager::RestoreAll() {
        RestorePatches();
        RestoreDetours();
        debug("[MemoryManager] Restored all detours and patches.");
    }

    bool MemoryManager::IsLocationModified(uintptr_t startAddress, size_t length, std::vector<std::string>* detectedKeys) {
        uintptr_t endAddress = startAddress + length;
        for (const auto& patchEntry : MemoryManager::Patches) {
            const std::shared_ptr<Patch> patch = patchEntry.second;
            if (patch->isPatched) {
                uintptr_t patchEnd = patch->targetAddress + static_cast<uintptr_t>(patch->patchBytes.size());
                if (startAddress < patchEnd && endAddress > patch->targetAddress) {
                    detectedKeys->push_back(patchEntry.first);
                }
            }
        }

        for (const auto& detourEntry : MemoryManager::Detours) {
            const std::shared_ptr<Detour> detour = detourEntry.second;
            if (detour->isPatched) {
                uintptr_t detourEnd = detour->targetAddress + sizeof(uintptr_t);
                if (startAddress < detourEnd && endAddress > detour->targetAddress) {
                    detectedKeys->push_back(detourEntry.first);
                }
            }
        }

        if (detectedKeys->size() > 0)
            return true;

        return false;
    }

    bool MemoryManager::IsAddressValid(uintptr_t address) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(GetCurrentProcess(), reinterpret_cast<void*>(address), &mbi, sizeof(mbi))) {
            return (mbi.State == MEM_COMMIT) &&
                (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                    PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));
        }
        return false;
    }

    bool MemoryManager::IsMemoryRangeValid(uintptr_t address, size_t length) {
        uintptr_t currentAddress = address;
        uintptr_t endAddress = address + length;

        while (currentAddress < endAddress) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(GetCurrentProcess(), reinterpret_cast<void*>(currentAddress), &mbi, sizeof(mbi))) {
                if (!(mbi.State == MEM_COMMIT) ||
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

    bool MemoryManager::IsAddressReadable(uintptr_t address)
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(GetCurrentProcess(), reinterpret_cast<void*>(address), &mbi, sizeof(mbi)))
        {
            return (mbi.State == MEM_COMMIT) &&
                (mbi.Protect & (PAGE_READONLY));
        }
        return false;
    }

    uintptr_t MemoryManager::ReadAddress(uintptr_t address) {
        uintptr_t results = NULL;

        if (address == NULL || !IsAddressValid(address))
            return NULL;

        __try {
            return *(reinterpret_cast<uintptr_t*>(address));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            error("Exception caught: access violation while attempting to read address: %lld", address);
            return NULL;
        }
    }

    std::string MemoryManager::CopyString(uintptr_t address, size_t maxLength) {
        const char* strPtr = nullptr;
        size_t length = 0;

        strPtr = reinterpret_cast<const char*>(address);

        while (length < maxLength && strPtr[length] != '\0') {
            ++length;
        }

        if (strPtr != nullptr)
            return std::string(strPtr, length);
        return strPtr;
    }

    std::string_view MemoryManager::ReadString(uintptr_t address)
    {
        const char* cstr = reinterpret_cast<const char*>(address);
        return std::string_view{ cstr };
    }

    uintptr_t MemoryManager::GetModuleBaseAddress(const wchar_t* moduleName)
    {
        HMODULE hMod = GetModuleHandleW(moduleName);
        if (!hMod) {
            error("%s not loaded yet.", moduleName);
            return 0;
        }
        else {
            uint8_t* base = reinterpret_cast<uint8_t*>(hMod);
            return reinterpret_cast<uintptr_t>(base);
        }
    }

    void MemoryManager::GetModuleBounds(const wchar_t* moduleName, uintptr_t& start, uintptr_t& end)
    {
        HMODULE hMod = GetModuleHandleW(moduleName);
        if (!hMod) {
            error("Module %ls not loaded yet!", moduleName);
            start = end = 0;
            return;
        }

        uint8_t* base = reinterpret_cast<uint8_t*>(hMod);
        IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        IMAGE_NT_HEADERS64* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);

        size_t moduleSize = nt->OptionalHeader.SizeOfImage;

        start = reinterpret_cast<uintptr_t>(base);
        end = start + moduleSize;
    }

    fs::path MemoryManager::ReadWindowsPath(const char* address) {
        std::string safe(address);

        constexpr std::string_view invalidChars = R"delim(<>:"/\|?*)delim";

        std::transform(safe.begin(), safe.end(), safe.begin(), [](char ch) {
            return (ch < 0x20 || invalidChars.find(ch) != std::string_view::npos) ? '_' : ch;
            });

        return safe;
    }

    fs::path MemoryManager::ReadWindowsPath(uintptr_t address) {
        return ReadWindowsPath(reinterpret_cast<const char*>(address));
    }

    void MemoryManager::WriteBufferToFile(const char* buffer, size_t length, const fs::path& outPath) {
        std::ofstream outFile(outPath, std::ios::binary);
        if (!outFile) {
            throw std::runtime_error("Failed to open file: " + outPath.string());
        }

        outFile.write(static_cast<const char*>(buffer), static_cast<std::streamsize>(length));
        outFile.close();
    }

    void MemoryManager::WriteBufferToFile(uintptr_t address, size_t length, const fs::path& outPath) {
        return WriteBufferToFile(reinterpret_cast<const char*>(address), length, outPath);
    }
}
