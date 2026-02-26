#pragma once

#include "ByteWeaverPCH.h"

#include <winternl.h>

namespace ByteWeaver::DebugTools {

    // If your SDK doesn't expose these, you may need to define NT_SUCCESS or include ntstatus headers.
    // This code relies on PEB/LDR structures from winternl.h (internal-ish Windows structs).

    // ------------------------------------------------------------
    // Small helpers (replace with your own "inline_*" versions if wanted)
    // ------------------------------------------------------------
    static inline bool StrEqA(const char* a, const char* b)
    {
        if (!a || !b) return false;
        while (*a && *b)
        {
            if (*a != *b) return false;
            ++a; ++b;
        }
        return (*a == '\0' && *b == '\0');
    }

    static inline wchar_t ToLowerW(wchar_t c)
    {
        return (c >= L'A' && c <= L'Z') ? (c + (L'a' - L'A')) : c;
    }

    // Case-insensitive equality for wide strings
    static inline bool StrEqIW(const wchar_t* a, const wchar_t* b)
    {
        if (!a || !b) return false;
        while (*a && *b)
        {
            if (ToLowerW(*a) != ToLowerW(*b))
                return false;
            ++a; ++b;
        }
        return (*a == L'\0' && *b == L'\0');
    }

    // ------------------------------------------------------------
    // Get PEB pointer (x86/x64)
    // ------------------------------------------------------------
    static inline PEB* GetPeb()
    {
    #if defined(_M_X64)
        return reinterpret_cast<PEB*>(__readgsqword(0x60));
    #elif defined(_M_IX86)
        return reinterpret_cast<PEB*>(__readfsdword(0x30));
    #else
    #   error Unsupported architecture
    #endif
    }

    // ------------------------------------------------------------
    // Find loaded module base by DLL name (e.g. L"kernel32.dll")
    // Uses BaseDllName (not FullDllName) for cleaner exact matching.
    // ------------------------------------------------------------
    static BYTE* FindLoadedModuleBase(const wchar_t* dllName)
    {
        if (!dllName) return nullptr;

        PEB* peb = GetPeb();
        if (!peb || !peb->Ldr) return nullptr;

        PPEB_LDR_DATA ldr = peb->Ldr;
        LIST_ENTRY* listHead = &ldr->InMemoryOrderModuleList;

        for (LIST_ENTRY* curr = listHead->Flink; curr != listHead; curr = curr->Flink)
        {
            auto* entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

            // Prefer BaseDllName (e.g. "kernel32.dll") instead of FullDllName path
            if (!entry->BaseDllName.Buffer)
                continue;

            if (StrEqIW(entry->BaseDllName.Buffer, dllName))
                return reinterpret_cast<BYTE*>(entry->DllBase);
        }

        return nullptr;
    }

    // ------------------------------------------------------------
    // Resolve an export by name from a loaded module base
    // (manual GetProcAddress)
    // ------------------------------------------------------------
    static void* ResolveExportByName(BYTE* moduleBase, const char* funcName)
    {
        if (!moduleBase || !funcName)
            return nullptr;

        // Validate DOS header
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(moduleBase);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) // "MZ"
            return nullptr;

        // Validate NT headers
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(moduleBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) // "PE\0\0"
            return nullptr;

        // Export directory
        const IMAGE_DATA_DIRECTORY& exportDirData =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        if (exportDirData.VirtualAddress == 0 || exportDirData.Size == 0)
            return nullptr;

        auto* exportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
            moduleBase + exportDirData.VirtualAddress);

        auto* nameRVAs = reinterpret_cast<DWORD*>(moduleBase + exportDir->AddressOfNames);
        auto* funcRVAs = reinterpret_cast<DWORD*>(moduleBase + exportDir->AddressOfFunctions);
        auto* ordinals = reinterpret_cast<WORD*>(moduleBase + exportDir->AddressOfNameOrdinals);

        // Search by exported name
        for (DWORD i = 0; i < exportDir->NumberOfNames; ++i)
        {
            const char* exportName = reinterpret_cast<const char*>(moduleBase + nameRVAs[i]);
            if (!StrEqA(exportName, funcName))
                continue;

            WORD ordinalIndex = ordinals[i];
            DWORD funcRva = funcRVAs[ordinalIndex];

            // NOTE:
            // If funcRva points inside the export directory range, it's a forwarded export.
            // This function does NOT resolve forwarders (e.g., "KERNELBASE.SleepEx").
            // You can add forwarder handling if needed.
            return reinterpret_cast<void*>(moduleBase + funcRva);
        }

        return nullptr;
    }

    // ------------------------------------------------------------
    // Public helper: manual GetProcAddress-like resolver
    // ------------------------------------------------------------
    __forceinline void* GetFuncAddressManual(const wchar_t* dllName, const char* funcName)
    {
    BYTE* moduleBase = FindLoadedModuleBase(dllName);
    if (!moduleBase)
        return nullptr;

    return ResolveExportByName(moduleBase, funcName);
}

}