// Copyright(C) 2025 0xKate - MIT License

#include "ByteWeaver.h"
#include "MemoryManager.h"

#include "AddressDB.h"
#include "WinPatch.h"
#include "WinDetour.h"

namespace ByteWeaver {

// static member definitions
std::map<std::string, std::shared_ptr<Patch>> MemoryManager::Patches;
std::map<std::string, std::shared_ptr<Detour>> MemoryManager::Detours;

std::shared_mutex MemoryManager::PatchesMutex;
std::shared_mutex MemoryManager::DetoursMutex;

uintptr_t MemoryManager::GetBaseAddress() {
    HMODULE hModule = GetModuleHandle(nullptr);
    return reinterpret_cast<uintptr_t>(hModule);
}

void MemoryManager::AddPatch(const std::string& key, std::shared_ptr<Patch> hPatch) {
    // Move out existing and insert new while holding mutex; call Restore on old after unlocking.
    std::shared_ptr<Patch> old;
    {
        std::unique_lock lock(PatchesMutex);
        if (const auto it = Patches.find(key); it != Patches.end()) {
            Warn("Patch with key '%s' already exists and will be replaced.", key.c_str());
            old = it->second;               // keep old to restore after unlock
            Patches.erase(it);
        }
        hPatch->Key = key.c_str();
        Patches.emplace(key, std::move(hPatch));
    } // unlock
    if (old) old->Restore();
}

void MemoryManager::AddPatch(const std::string& key, Patch* hPatch) {
    AddPatch(key, std::shared_ptr<Patch>(hPatch));
}

void MemoryManager::ErasePatch(const std::string& key) {
    std::unique_lock lock(PatchesMutex);
    if (const auto it = Patches.find(key); it != Patches.end()) {
        Patches.erase(it);
    }
}

void MemoryManager::RestoreAndErasePatch(const std::string& key) {
    // Move out the object while holding lock, erase, then call Restore() outside lock.
    std::shared_ptr<Patch> toRestore;
    {
        std::unique_lock lock(PatchesMutex);
        if (const auto it = Patches.find(key); it != Patches.end()) {
            toRestore = it->second;
            Patches.erase(it);
        }
    }
    if (toRestore) toRestore->Restore();
}

void MemoryManager::AddDetour(const std::string& key, std::shared_ptr<Detour> hDetour) {
    std::shared_ptr<Detour> old;
    {
        std::unique_lock lock(DetoursMutex);
        if (const auto it = Detours.find(key); it != Detours.end()) {
            Warn("Detour with key '%s' already exists and will be replaced.", key.c_str());
            old = it->second;
            Detours.erase(it);
        }
        hDetour->Key = key.c_str();
        Detours.emplace(key, std::move(hDetour));
    }
    if (old) old->Restore();
}

void MemoryManager::AddDetour(const std::string& key, Detour* hDetour) {
    AddDetour(key, std::shared_ptr<Detour>(hDetour));
}

void MemoryManager::EraseDetour(const std::string& key) {
    std::unique_lock lock(DetoursMutex);
    if (const auto it = Detours.find(key); it != Detours.end()) {
        Detours.erase(it);
    }
}

void MemoryManager::RestoreAndEraseDetour(const std::string& key) {
    std::shared_ptr<Detour> toRestore;
    {
        std::unique_lock lock(DetoursMutex);
        if (const auto it = Detours.find(key); it != Detours.end()) {
            toRestore = it->second;
            Detours.erase(it);
        }
    }
    if (toRestore) toRestore->Restore();
}

void MemoryManager::ApplyPatches() {
    // copy pointers to call Apply() outside lock
    std::vector<std::shared_ptr<Patch>> toApply;
    {
        std::shared_lock lock(PatchesMutex);
        toApply.reserve(Patches.size());
        for (const auto& val : Patches | std::views::values) {
            if (auto const& ptr = val; ptr && ptr->IsEnabled) toApply.push_back(ptr);
        }
    } // unlock
    for (auto& p : toApply) if (p) p->Apply();
}

void MemoryManager::RestorePatches() {
    std::vector<std::shared_ptr<Patch>> toRestore;
    {
        std::shared_lock lock(PatchesMutex);
        toRestore.reserve(Patches.size());
        for (const auto& val : Patches | std::views::values) {
            if (auto const& ptr = val; ptr && ptr->IsPatched) toRestore.push_back(ptr);
        }
    }
    for (auto& p : toRestore) if (p) p->Restore();
}

void MemoryManager::ApplyDetours() {
    std::vector<std::shared_ptr<Detour>> toApply;
    {
        std::shared_lock lock(DetoursMutex);
        toApply.reserve(Detours.size());
        for (const auto& val : Detours | std::views::values) {
            if (auto const& ptr = val) toApply.push_back(ptr);
        }
    }
    for (auto& d : toApply) if (d) d->Apply();
}

void MemoryManager::RestoreDetours() {
    std::vector<std::shared_ptr<Detour>> toRestore;
    {
        std::shared_lock lock(DetoursMutex);
        toRestore.reserve(Detours.size());
        for (const auto& val : Detours | std::views::values) {
            if (auto const& ptr = val) toRestore.push_back(ptr);
        }
    }
    for (auto& d : toRestore) if (d) d->Restore();
}

void MemoryManager::ApplyByKey(const std::string& key) {
    // Always lock PatchesMutex then DetoursMutex to preserve ordering and avoid deadlocks.
    std::shared_ptr<Patch> sp;
    std::shared_ptr<Detour> sd;
    {
        std::shared_lock lockP(PatchesMutex);
        if (const auto itP = Patches.find(key); itP != Patches.end()) sp = itP->second;
    }
    {
        std::shared_lock lockD(DetoursMutex);
        if (const auto itD = Detours.find(key); itD != Detours.end()) sd = itD->second;
    }

    if (sd) sd->Apply();
    if (sp) sp->Apply();
}

void MemoryManager::RestoreByKey(const std::string& key) {
    std::shared_ptr<Patch> sp;
    std::shared_ptr<Detour> sd;
    {
        std::shared_lock lockP(PatchesMutex);
        if (const auto itP = Patches.find(key); itP != Patches.end()) sp = itP->second;
    }
    {
        std::shared_lock lockD(DetoursMutex);
        if (const auto itD = Detours.find(key); itD != Detours.end()) sd = itD->second;
    }

    if (sp) sp->Restore();
    if (sd) sd->Restore();
}

void MemoryManager::ApplyAll() {
    // Apply detours first then patches (as original). Each function handles locking/copying.
    ApplyDetours();
    ApplyPatches();
    Debug("[MemoryManager] Applied all detours and enabled patches!");
}

void MemoryManager::RestoreAll() {
    // Restore patches then detours (as original).
    RestorePatches();
    RestoreDetours();
    Debug("[MemoryManager] Restored all detours and patches.");
}

void MemoryManager::ClearAll() {
    // clear both maps while holding both mutexes. Lock order: Patches then Detours.
    std::scoped_lock lock(PatchesMutex, DetoursMutex);
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
