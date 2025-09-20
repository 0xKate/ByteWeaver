// Copyright(C) 2025 0xKate - MIT License

#include "ByteWeaver.h"
#include "MemoryManager.h"

#include <ranges>
#include <utility>
#include "WinPatch.h"
#include "WinDetour.h"


namespace ByteWeaver {
    std::map<std::string, std::shared_ptr<Patch>> MemoryManager::Patches;
    std::map<std::string, std::shared_ptr<Detour>> MemoryManager::Detours;

    uintptr_t MemoryManager::GetBaseAddress() {
        HMODULE hModule = GetModuleHandle(nullptr);
        return reinterpret_cast<uintptr_t>(hModule);
    }

    void MemoryManager::AddPatch(const std::string& key, std::shared_ptr<Patch> hPatch) {
        if (const auto it = Patches.find(key); it != Patches.end()) {
            Warn("Patch with key '%s' already exists and will be replaced.", key.c_str());
            RestoreAndErasePatch(key);
        }
        Patches[key] = std::move(hPatch);
    }

    void MemoryManager::AddPatch(const std::string& key, Patch* hPatch) {
        AddPatch(key, std::shared_ptr<Patch>(hPatch));
    }

    void MemoryManager::ErasePatch(const std::string& key) {
        if (const auto it = Patches.find(key); it != Patches.end()) {
            Patches.erase(it);
        }
    }

    void MemoryManager::RestoreAndErasePatch(const std::string& key) {
        if (const auto it = Patches.find(key); it != Patches.end()) {
            it->second->Restore();
            Patches.erase(it);
        }
    }

    void MemoryManager::AddDetour(const std::string& key, std::shared_ptr<Detour> hDetour) {
        if (const auto it = Detours.find(key); it != Detours.end()) {
            Warn("Detour with key '%s' already exists and will be replaced.", key.c_str());
            RestoreAndEraseDetour(key);
        }
        Detours[key] = std::move(hDetour);
    }

    void MemoryManager::AddDetour(const std::string& key, Detour* hDetour) {
        AddDetour(key, std::shared_ptr<Detour>(hDetour));
    }

    void MemoryManager::EraseDetour(const std::string& key) {
        if (const auto it = Detours.find(key); it != Detours.end()) {
            Detours.erase(it);
        }
    }

    void MemoryManager::RestoreAndEraseDetour(const std::string& key) {
        if (const auto it = Detours.find(key); it != Detours.end()) {
            it->second->Restore();
            Detours.erase(it);
        }
    }

    void MemoryManager::ApplyPatches() {
        for (auto& val : Patches | std::views::values) {
            if (const std::shared_ptr<Patch>& patch = val; patch && patch->IsEnabled) {
                patch->Apply();
            }
        }
    }

    void MemoryManager::RestorePatches() {
        for (const auto& val : Patches | std::views::values) {
            if (const std::shared_ptr<Patch> patch = val; patch && patch->IsPatched) {
                patch->Restore();
            }
        }
    }

    void MemoryManager::ApplyDetours() {
        for (const auto& val : Detours | std::views::values) {
            if (std::shared_ptr<Detour> detour = val; detour != nullptr) {
                detour->Apply();
            }
        }
    }

    void MemoryManager::RestoreDetours() {
        for (const auto& val : Detours | std::views::values) {
            if (std::shared_ptr<Detour> detour = val; detour != nullptr) {
                detour->Restore();
            }
        }
    }

    void MemoryManager::ApplyByKey(const std::string& key) {
        if (const auto itDetour = Detours.find(key); itDetour != Detours.end())
            itDetour->second->Apply();

        if (const auto itPatch = Patches.find(key); itPatch != Patches.end())
            itPatch->second->Apply();
    }

    void MemoryManager::RestoreByKey(const std::string& key) {
        if (const auto itPatch = Patches.find(key); itPatch != Patches.end())
            itPatch->second->Restore();

        if (const auto itDetour = Detours.find(key); itDetour != Detours.end())
            itDetour->second->Restore();
    }

    void MemoryManager::ApplyAll() {
        ApplyDetours();
        ApplyPatches();
        Debug("[MemoryManager] Applied all detours and enabled patches!");
    }

    void MemoryManager::RestoreAll() {
        RestorePatches();
        RestoreDetours();
        Debug("[MemoryManager] Restored all detours and patches.");
    }

    void MemoryManager::ClearAll() {
        Patches.clear();
        Detours.clear();
    }

    bool MemoryManager::IsLocationModified(const uintptr_t address, const size_t length, std::vector<std::string>* detectedKeys) {
        const uintptr_t endAddress = address + length;
        for (const auto& [fst, snd] : Patches) {
            if (const std::shared_ptr<Patch> patch = snd; patch->IsPatched) {
                if (const uintptr_t patchEnd = patch->TargetAddress + patch->PatchBytes.size(); address < patchEnd && endAddress > patch->TargetAddress) {
                    detectedKeys->push_back(fst);
                }
            }
        }

        for (const auto& [fst, snd] : Detours) {
            if (const std::shared_ptr<Detour> detour = snd; detour->IsPatched) {
                if (const uintptr_t detourEnd = detour->TargetAddress + detour->Size; address < detourEnd && endAddress > detour->TargetAddress) {
                    detectedKeys->push_back(fst);
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
        for (uint8_t b : data) {
            oss << std::setw(2) << static_cast<unsigned>(b);
        }
        return oss.str();
    }

}
