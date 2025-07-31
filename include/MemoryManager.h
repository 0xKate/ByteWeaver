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

		static void AddPatch(std::string key, std::shared_ptr<Patch> hPatch);
		static void DelPatch(std::string key);

		static void AddDetour(std::string key, Detour* hDetour);
		static void AddDetour(std::string key, std::shared_ptr<Detour> hDetour);
		static void EraseDetour(std::string key);
		static void DelDetour(std::string key);

		static void ApplyPatches();
		static void RestorePatches();

		static void ApplyDetours();
		static void RestoreDetours();

		static void ApplyByKey(std::string key);
		static void RestoreByKey(std::string key);

		static void ApplyAll();
		static void RestoreAll();

		static bool IsLocationModified(uintptr_t startAddress, int length, std::vector<std::string>* detectedKeys);
		static bool IsAddressValid(uintptr_t lpAddress);
		static bool IsMemoryRangeValid(uintptr_t address, size_t length);
		static bool IsAddressReadable(uintptr_t address);
		static uintptr_t ReadAddress(uintptr_t address);
		static std::string CopyString(uintptr_t address, size_t maxLength = 64);
		static std::string_view ReadString(uintptr_t address);

		static uintptr_t GetModuleBaseAddress(const wchar_t* moduleName);
		static void GetModuleBounds(const wchar_t* moduleName, uintptr_t& start, uintptr_t& end);

		static fs::path ReadWindowsPath(const char* cstr);
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
