// Copyright(C) 2025 0xKate - MIT License

#pragma once
#include "WinDetour.h"
#include "WinPatch.h"

namespace ByteWeaver {
	class MemoryManager
	{
	public:
		static uintptr_t BaseAddress;

		static std::map<std::string, std::shared_ptr<MemoryModification>> Mods;
		static std::shared_mutex ModsMutex;

		static uintptr_t GetBaseAddress();
		static bool ModExists(const std::string& key, std::shared_ptr<MemoryModification>* hOutMod = nullptr);
		static bool AddMod(const std::string& key, std::shared_ptr<MemoryModification> hMod, uint16_t groupID = 0x0000);
		static bool EraseMod(const std::string& key);
		static auto GetMod(const std::string& key) -> std::shared_ptr<MemoryModification>;
		static bool ApplyMod(const std::string& key);
		static bool RestoreMod(const std::string& key);
		static bool RestoreAndEraseMod(const std::string& key);
		static bool EnableMod(const std::string& key);
		static bool DisableMod(const std::string& key);

		static bool CreatePatch(const std::string& key, uintptr_t patchAddress, std::vector<uint8_t> patchBytes, uint16_t groupID = 0x0000);
		static bool CreateDetour(const std::string& key, uintptr_t targetAddress, PVOID* originalFunction, PVOID detourFunction, uint16_t groupID = 0x0000);

		static auto GetAllMods() -> std::vector<std::shared_ptr<MemoryModification>>;
		static bool ApplyAllMods(); // Only Applies Enabled Mods. (Use EnableAll if you truly want everything on.)
		static bool RestoreAllMods();
		static void RestoreAndEraseAllMods();
		static void EraseAllMods();
		static bool EnableAllMods();
		static bool DisableAllMods();

		static auto GetModsByGroupID(uint16_t groupID) -> std::vector<std::shared_ptr<MemoryModification>>;
		static bool ApplyByGroupID(uint16_t groupID); // Only Applies Enabled Mods. (Use EnableByGroupID if you truly want everything on.)
		static bool RestoreByGroupID(uint16_t groupID);
		static void EraseByGroupID(uint16_t groupID); // Erase entire group id (Does not restore)
		static void RestoreAndEraseByGroupID(uint16_t groupID);
		static bool EnableAllByGroupID(uint16_t groupID);
		static bool DisableAllByGroupID(uint16_t groupID);

		static auto GetModsByType(ModType modType) -> std::vector<std::shared_ptr<MemoryModification>>;
		static bool ApplyByType(ModType modType); // Only Applies Enabled Mods. (Use EnableAllByType if you truly want everything on)
		static bool RestoreByType(ModType modType);
		static void EraseByType(ModType modType); // Erase all by type (Does not restore)
		static void RestoreAndEraseByType(ModType modType);
		static bool EnableAllByType(ModType modType);
		static bool DisableAllByType(ModType modType);



		// --- START Deprecated

		static bool AddPatch(const std::string& key, const std::shared_ptr<Patch>& hPatch, uint16_t groupID = 0x0000);
		static bool AddPatch(const std::string& key, Patch* patch, uint16_t groupID = 0x0000);
		static bool ErasePatch(const std::string& key);
		static bool RestoreAndErasePatch(const std::string& key);

		static bool ApplyPatches();
		static bool RestorePatches();

		static bool AddDetour(const std::string& key, const std::shared_ptr<Detour>& hDetour, uint16_t groupID = 0x0000);
		static bool AddDetour(const std::string& key, Detour* detour, uint16_t groupID = 0x0000);
		static bool EraseDetour(const std::string& key);
		static bool RestoreAndEraseDetour(const std::string& key);

		static bool ApplyDetours();
		static bool RestoreDetours();

		static bool ApplyAll();
		static bool RestoreAll();
		static void ClearAll();

		static void ApplyByKey(const std::string& key);
		static void RestoreByKey(const std::string& key);

		// --- END Deprecated

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

		static std::vector<uint8_t> ReadBytesSafe(uintptr_t address, size_t size);
		static std::string BytesToHex(const std::vector<uint8_t>& data);

		template<typename T>
		static T Read(uintptr_t address) {
			return *reinterpret_cast<T*>(address);
		}

		template<typename T>
		static void Write(uintptr_t address, T value) {
			*reinterpret_cast<T*>(address) = value;
		}
	};
}