// Copyright(C) 2025 0xKate - MIT License

#pragma once
#include "WinDetour.h"
#include "WinPatch.h"

namespace ByteWeaver {
	class MemoryManager
	{
	public:
		static uintptr_t BaseAddress;
		static std::map<std::string, std::shared_ptr<Patch>> Patches;
		static std::map<std::string, std::shared_ptr<Detour>> Detours;

		static uintptr_t GetBaseAddress();

		static void AddPatch(const std::string& key, std::shared_ptr<Patch> hPatch);
		static void AddPatch(const std::string& key, Patch* hPatch);
		static void ErasePatch(const std::string& key);
		static void RestoreAndErasePatch(const std::string& key);

		static void AddDetour(const std::string& key, std::shared_ptr<Detour> hDetour);
		static void AddDetour(const std::string& key, Detour* hDetour);
		static void EraseDetour(const std::string& key);
		static void RestoreAndEraseDetour(const std::string& key);

		static void ApplyPatches();
		static void RestorePatches();

		static void ApplyDetours();
		static void RestoreDetours();

		static void ApplyByKey(const std::string& key);
		static void RestoreByKey(const std::string& key);

		static void ApplyAll();
		static void RestoreAll();

		static bool IsLocationModified(uintptr_t address, size_t length, std::vector<std::string>* detectedKeys);
		static bool IsAddressValid(uintptr_t address);
		static bool IsMemoryRangeValid(uintptr_t address, size_t length);
		static bool IsAddressReadable(uintptr_t address);
		static uintptr_t ReadAddress(uintptr_t address);
		static std::string ReadStringSafe(uintptr_t address, size_t maxLength = 64);
		static std::string ReadString(uintptr_t address);

		static uintptr_t GetModuleBaseAddress(const wchar_t* moduleName);
		static uintptr_t GetModuleBaseAddressFast(const void* p);
		static uintptr_t GetModuleBaseAddressFast(uintptr_t address);
		static std::pair<uintptr_t, uintptr_t> GetModuleBounds(uintptr_t address);
		static fs::path GetModulePath(uintptr_t moduleBase);

#ifdef _WIN64
		static std::pair<uintptr_t, uintptr_t> GetFunctionBounds(uintptr_t address);
#endif

		static fs::path ReadWindowsPath(const char* address);
		static fs::path ReadWindowsPath(uintptr_t address);
		static void WriteBufferToFile(uintptr_t address, size_t length, const fs::path& outPath);
		static void WriteBufferToFile(const char* buffer, size_t length, const fs::path& outPath);

		template<typename T>
		static T Read(uintptr_t address) {
			return *(reinterpret_cast<T*>(address));
		}

		template<typename T>
		static void Write(uintptr_t address, T value) {
			*(reinterpret_cast<T*>(address)) = value;
		}
	};
}