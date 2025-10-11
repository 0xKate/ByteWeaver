// Copyright(C) 2025 0xKate - MIT License

#pragma once

#include <ByteWeaverPCH.h>
#include <MemoryModification.h>

#include "WinDetour.h"
#include "WinPatch.h"

namespace ByteWeaver {
	/**
	 * @brief Comprehensive memory management system for runtime memory modification and inspection
	 *
	 * The MemoryManager class provides static utilities for creating, applying, and managing
	 * memory patches and function detours. It supports organized modification management through
	 * groups and types, along with various memory validation and inspection capabilities.
	 */
	class MemoryManager
	{
	public:
		/// @brief Base address of the target process/module
		static uintptr_t BaseAddress;

		/// @brief Container for all registered memory modifications
		static std::map<std::string, std::shared_ptr<MemoryModification>> Mods;

		/// @brief Thread-safe access control for the modifications map
		static std::shared_mutex ModsMutex;

		/**
		 * @brief Retrieves the base address of the target process or module
		 * @return The base address as uintptr_t
		 */
		static uintptr_t GetBaseAddress();

		/**
		 * @brief Checks if a memory modification with the specified key exists
		 * @param key Unique identifier for the modification
		 * @param hOutMod Optional output parameter to receive the modification object
		 * @return true if modification exists, false otherwise
		 */
		static bool ModExists(const std::string& key, std::shared_ptr<MemoryModification>* hOutMod = nullptr);

		/**
		 * @brief Adds a new memory modification to the manager
		 * @param key Unique identifier for the modification
		 * @param hMod Shared pointer to the memory modification object
		 * @param groupID Optional group identifier for batch operations (default: 0x0000)
		 * @return true on success, false on failure
		 */
		static bool AddMod(const std::string& key, std::shared_ptr<MemoryModification> hMod, uint16_t groupID = 0x0000);

		/**
		 * @brief Adds a memory patch modification to the manager by value
		 * @param key Unique identifier for the patch
		 * @param patch Patch object containing the modification details
		 * @param groupID Optional group identifier for batch operations (default: 0x0000)
		 * @return true on success, false on failure
		 */
		static bool AddMod(const std::string& key, Patch* patch, uint16_t groupID = 0x0000);

		/**
		 * @brief Adds a function detour modification to the manager by value
		 * @param key Unique identifier for the detour
		 * @param detour Detour object containing the detour details
		 * @param groupID Optional group identifier for batch operations (default: 0x0000)
		 * @return true on success, false on failure
		 */
		static bool AddMod(const std::string& key, Detour* detour, uint16_t groupID = 0x0000);

		/**
		 * @brief Adds a memory patch modification to the manager using a shared pointer
		 * @param key Unique identifier for the patch
		 * @param hPatch Shared pointer to the patch object
		 * @param groupID Optional group identifier for batch operations (default: 0x0000)
		 * @return true on success, false on failure
		 */
		static bool AddMod(const std::string& key, const std::shared_ptr<Patch>& hPatch, uint16_t groupID = 0x0000);

		/**
		 * @brief Adds a function detour modification to the manager using a shared pointer
		 * @param key Unique identifier for the detour
		 * @param hDetour Shared pointer to the detour object
		 * @param groupID Optional group identifier for batch operations (default: 0x0000)
		 * @return true on success, false on failure
		 */
		static bool AddMod(const std::string& key, const std::shared_ptr<Detour>& hDetour, uint16_t groupID = 0x0000);

		/**
		 * @brief Removes a memory modification from the manager
		 * @param key Unique identifier of the modification to remove
		 * @return true on success, false if modification doesn't exist
		 */
		static bool EraseMod(const std::string& key);

		/**
		 * @brief Retrieves a specific memory modification by key
		 * @param key Unique identifier of the modification
		 * @return Shared pointer to the modification, or nullptr if not found
		 */
		static auto GetMod(const std::string& key) -> std::shared_ptr<MemoryModification>;

		/**
		 * @brief Applies a specific memory modification
		 * @param key Unique identifier of the modification to apply
		 * @return true on success, false on failure
		 */
		static bool ApplyMod(const std::string& key);

		/**
		 * @brief Restores the original memory state for a specific modification
		 * @param key Unique identifier of the modification to restore
		 * @return true on success, false on failure
		 */
		static bool RestoreMod(const std::string& key);

		/**
		 * @brief Restores the original memory state and removes the modification from the manager
		 * @param key Unique identifier of the modification
		 * @return true on success, false on failure
		 */
		static bool RestoreAndEraseMod(const std::string& key);

		/**
		 * @brief Creates and registers a memory patch modification
		 * @param key Unique identifier for the patch
		 * @param patchAddress Memory address to patch
		 * @param patchBytes Byte sequence to write at the address
		 * @param groupID Optional group identifier (default: 0x0000)
		 * @return true on success, false on failure
		 */
		static bool CreatePatch(const std::string& key, uintptr_t patchAddress, std::vector<uint8_t> patchBytes, uint16_t groupID = 0x0000);

		/**
		 * @brief Creates and registers a function detour modification
		 * @param key Unique identifier for the detour
		 * @param targetAddress Address of the function to detour
		 * @param originalFunction Pointer to store the original function address
		 * @param detourFunction Address of the replacement function
		 * @param groupID Optional group identifier (default: 0x0000)
		 * @return true on success, false on failure
		 */
		static bool CreateDetour(const std::string& key, uintptr_t targetAddress, PVOID* originalFunction, PVOID detourFunction, uint16_t groupID = 0x0000);

		/**
		 * @brief Retrieves all registered memory modifications
		 * @return Vector of all modification objects
		 */
		static auto GetAllMods() -> std::vector<std::shared_ptr<MemoryModification>>;

		/**
		 * @brief Applies all registered memory modifications
		 * @return true if all modifications applied successfully, false otherwise
		 */
		static bool ApplyAllMods();

		/**
		 * @brief Restores all memory modifications to their original state
		 * @return true if all modifications restored successfully, false otherwise
		 */
		static bool RestoreAllMods();

		/**
		 * @brief Restores all modifications and removes them from the manager
		 */
		static void RestoreAndEraseAllMods();

		/**
		 * @brief Removes all modifications from the manager without restoring
		 */
		static void EraseAllMods();

		/**
		 * @brief Retrieves all modifications belonging to a specific group
		 * @param groupID Group identifier to filter by
		 * @return Vector of modifications in the specified group
		 */
		static auto GetModsByGroupID(uint16_t groupID) -> std::vector<std::shared_ptr<MemoryModification>>;

		/**
		 * @brief Applies all modifications in a specific group
		 * @param groupID Group identifier
		 * @return true if all group modifications applied successfully
		 */
		static bool ApplyByGroupID(uint16_t groupID);

		/**
		 * @brief Restores all modifications in a specific group
		 * @param groupID Group identifier
		 * @return true if all group modifications restored successfully
		 */
		static bool RestoreByGroupID(uint16_t groupID);

		/**
		 * @brief Removes all modifications in a specific group from the manager
		 * @param groupID Group identifier
		 */
		static void EraseByGroupID(uint16_t groupID);

		/**
		 * @brief Restores and removes all modifications in a specific group
		 * @param groupID Group identifier
		 */
		static void RestoreAndEraseByGroupID(uint16_t groupID);

		/**
		 * @brief Retrieves all modifications of a specific type
		 * @param modType Type of modifications to retrieve
		 * @return Vector of modifications of the specified type
		 */
		static auto GetModsByType(ModType modType) -> std::vector<std::shared_ptr<MemoryModification>>;

		/**
		 * @brief Applies all modifications of a specific type
		 * @param modType Type of modifications to apply
		 * @return true if all type modifications applied successfully
		 */
		static bool ApplyByType(ModType modType);

		/**
		 * @brief Restores all modifications of a specific type
		 * @param modType Type of modifications to restore
		 * @return true if all type modifications restored successfully
		 */
		static bool RestoreByType(ModType modType);

		/**
		 * @brief Removes all modifications of a specific type from the manager
		 * @param modType Type of modifications to remove
		 */
		static void EraseByType(ModType modType);

		/**
		 * @brief Restores and removes all modifications of a specific type
		 * @param modType Type of modifications to process
		 */
		static void RestoreAndEraseByType(ModType modType);

		static bool DoRangesIntersect(uintptr_t addr1, size_t size1, uintptr_t addr2, size_t size2);

		/**
		 * @brief Checks if a memory region has been modified by any registered modifications
		 * @param address Starting address of the region to check
		 * @param length Size of the region in bytes
		 * @param detectedKeys Optional output parameter to receive keys of modifications affecting the region
		 * @return true if the region is modified, false otherwise
		 */
		static bool IsLocationModified(uintptr_t address, size_t length, std::vector<std::string>* detectedKeys);

		/**
		 * @brief Validates if a memory address is accessible
		 * @param address Memory address to validate
		 * @return true if address is valid, false otherwise
		 */
		static bool IsAddressValid(uintptr_t address);

		/**
		 * @brief Validates if a memory range is accessible
		 * @param address Starting address of the range
		 * @param length Size of the range in bytes
		 * @return true if range is valid, false otherwise
		 */
		static bool IsMemoryRangeValid(uintptr_t address, size_t length);

		/**
		 * @brief Checks if a memory address can be read from
		 * @param address Memory address to check
		 * @return true if address is readable, false otherwise
		 */
		static bool IsAddressReadable(uintptr_t address);

		/**
		 * @brief Reads a pointer value from memory
		 * @param address Memory address to read from
		 * @return Pointer value at the specified address
		 */
		static uintptr_t ReadAddress(uintptr_t address);

		/**
		 * @brief Safely reads a string from memory with length bounds
		 * @param address Memory address to read from
		 * @param maxLength Maximum characters to read (default: 64)
		 * @return String content, or empty string if read fails
		 */
		static std::string ReadStringSafe(uintptr_t address, size_t maxLength = 64);

		/**
		 * @brief Reads a null-terminated string from memory
		 * @param address Memory address to read from
		 * @return String content
		 */
		static std::string ReadString(uintptr_t address);

		/**
		 * @brief Gets the base address of a loaded module by name
		 * @param moduleName Wide character name of the module
		 * @return Base address of the module, or 0 if not found
		 */
		static uintptr_t GetModuleBaseAddress(const wchar_t* moduleName);

		/**
		 * @brief Quickly determines the module base address for a given pointer
		 * @param p Pointer within the module
		 * @return Base address of the containing module
		 */
		static uintptr_t GetModuleBaseAddressFast(const void* p);

		/**
		 * @brief Quickly determines the module base address for a given address
		 * @param address Address within the module
		 * @return Base address of the containing module
		 */
		static uintptr_t GetModuleBaseAddressFast(uintptr_t address);

		/**
		 * @brief Gets the start and end addresses of the module containing the given address
		 * @param address Address within the module
		 * @return Pair containing start and end addresses of the module
		 */
		static std::pair<uintptr_t, uintptr_t> GetModuleBounds(uintptr_t address);

		/**
		 * @brief Gets the file path of a module from its base address
		 * @param moduleBase Base address of the module
		 * @return Filesystem path to the module file
		 */
		static fs::path GetModulePath(uintptr_t moduleBase);

#ifdef _WIN64
		/**
		 * @brief Gets the start and end addresses of a function containing the given address
		 * @param address Address within the function
		 * @return Pair containing start and end addresses of the function
		 * @note Only available on Windows x64 builds
		 */
		static std::pair<uintptr_t, uintptr_t> GetFunctionBounds(uintptr_t address);
#endif

		/**
		 * @brief Reads a Windows file path from a character pointer
		 * @param address Pointer to null-terminated path string
		 * @return Filesystem path object
		 */
		static fs::path ReadWindowsPath(const char* address);

		/**
		 * @brief Reads a Windows file path from memory
		 * @param address Memory address containing null-terminated path string
		 * @return Filesystem path object
		 */
		static fs::path ReadWindowsPath(uintptr_t address);

		/**
		 * @brief Writes a memory buffer to a file
		 * @param address Memory address of the buffer
		 * @param length Size of the buffer in bytes
		 * @param outPath Output file path
		 */
		static void WriteBufferToFile(uintptr_t address, size_t length, const fs::path& outPath);

		/**
		 * @brief Writes a character buffer to a file
		 * @param buffer Pointer to the buffer
		 * @param length Size of the buffer in bytes
		 * @param outPath Output file path
		 */
		static void WriteBufferToFile(const char* buffer, size_t length, const fs::path& outPath);

		/**
		 * @brief Safely reads a sequence of bytes from memory
		 * @param address Memory address to read from
		 * @param size Number of bytes to read
		 * @return Vector containing the read bytes, or empty vector if read fails
		 */
		static std::vector<uint8_t> ReadBytesSafe(uintptr_t address, size_t size);

		/**
		 * @brief Converts byte data to hexadecimal string representation
		 * @param data Vector of bytes to convert
		 * @return Hexadecimal string representation
		 */
		static std::string BytesToHex(const std::vector<uint8_t>& data);

		/**
		 * @brief Template method for reading typed data from memory
		 * @tparam T Type of data to read
		 * @param address Memory address to read from
		 * @return Value of type T at the specified address
		 * @example int value = MemoryManager::Read<int>(0x12345678);
		 */
		template<typename T>
		static T Read(uintptr_t address) {
			return *reinterpret_cast<T*>(address);
		}

		/**
		 * @brief Template method for writing typed data to memory
		 * @tparam T Type of data to write
		 * @param address Memory address to write to
		 * @param value Value to write
		 * @example MemoryManager::Write<int>(0x12345678, 42);
		 */
		template<typename T>
		static void Write(uintptr_t address, T value) {
			*reinterpret_cast<T*>(address) = value;
		}
	};
}
