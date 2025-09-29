// Copyright(C) 2025 0xKate - MIT License

#pragma once

#include <ByteWeaverPCH.h>

namespace ByteWeaver {

    /**
     * @brief Type alias for address search results containing module info and found address.
     *
     * SearchResults is an optional tuple containing:
     * - First element (uintptr_t): Base address of the module
     * - Second element (uintptr_t): Absolute address where the signature/symbol was found
     * - Third element (uintptr_t): Offset from module base to the found address
     *
     * Returns std::nullopt if the search operation fails.
     */
    typedef std::optional<std::tuple<uintptr_t, uintptr_t, uintptr_t>> SearchResults;

    /**
     * @brief Static utility class for scanning memory and finding function addresses.
     *
     * AddressScanner provides functionality for locating functions and code patterns
     * in loaded modules using various search methods including:
     * - Pattern/signature scanning (AOB - Array of Bytes)
     * - Export table lookups
     * - Module-based searches with offset calculation
     *
     * This class is commonly used for reverse engineering, hooking, and dynamic
     * analysis where function addresses need to be resolved at runtime.
     *
     * ## Usage Examples:
     *
     * ### Pattern Scanning:
     * ```cpp
     * // Search for a byte pattern in kernel32.dll
     * auto result = AddressScanner::ModuleSearch(L"kernel32.dll", "CreateFileW_Pattern",
     *                                           "48,8B,C4,48,89,58,08,48,89,68,10");
     * if (result) {
     *     auto [moduleBase, foundAddress, offset] = *result;
     *     // Use foundAddress for hooking or analysis
     * }
     * ```
     *
     * ### Export Lookup:
     * ```cpp
     * // Find exported function address
     * auto result = AddressScanner::LookupExportAddress(L"kernel32.dll", "CreateFileW");
     * if (result) {
     *     auto [moduleBase, exportAddress, offset] = *result;
     *     // Use exportAddress directly
     * }
     * ```
     *
     * @note All methods are static and thread-safe for read operations
     * @warning Pattern scanning can be slow on large modules - use specific patterns when possible
     */
    class AddressScanner {
    public:
        /**
         * @brief Parses a comma-separated hex string into a searchable byte pattern.
         *
         * Converts a string representation of bytes into a vector of optional bytes
         * where wildcards ("?" or "??") become std::nullopt and hex values become
         * their corresponding byte values.
         *
         * @param patternStr Comma-separated string of hex bytes and wildcards
         *                   Example: "48,8B,C4,?,89,58,08" or "0x48,0x8B,??,0x89"
         *
         * @return Vector of optional bytes where nullopt represents wildcards
         *
         * @note Supports both "?" and "??" as wildcard representations
         * @note Hex values can be with or without "0x" prefix
         *
         * ### Example:
         * ```cpp
         * auto pattern = ParsePattern("48,8B,?,89,58");
         * // Results in: [0x48, 0x8B, nullopt, 0x89, 0x58]
         * ```
         */
        static std::vector<std::optional<uint8_t>> ParsePattern(const std::string& patternStr);

        /**
         * @brief Searches for a byte pattern within a memory region.
         *
         * Performs a linear search through the specified memory region looking for
         * the given pattern, supporting wildcards for flexible matching.
         *
         * @param base Pointer to the start of the memory region to search
         * @param size Size of the memory region in bytes
         * @param pattern Vector of optional bytes representing the search pattern
         * @param skipCount Number of matches to skip before returning (default: 0)
         *
         * @return Optional containing the address of the found pattern, or std::nullopt if not found
         *
         * @note The skipCount parameter allows finding the Nth occurrence of a pattern
         * @warning Ensure the memory region is readable to avoid access violations
         * @warning Large memory regions may take significant time to search
         *
         * ### Example:
         * ```cpp
         * auto pattern = ParsePattern("48,8B,C4,?");
         * auto address = FindSignature(moduleBase, moduleSize, pattern, 1); // Skip first match
         * ```
         */
        static std::optional<uintptr_t> FindSignature(uint8_t* base, size_t size,
                                                     const std::vector<std::optional<uint8_t>>& pattern,
                                                     size_t skipCount = 0);

        /**
         * @brief Searches for a byte pattern within a specific loaded module.
         *
         * Convenience overload that accepts a string pattern and automatically parses it
         * before searching within the specified module's memory space.
         *
         * @param moduleName Wide string name of the target module (e.g., L"kernel32.dll")
         * @param symbolName Descriptive name for logging purposes
         * @param signature Comma-separated hex string pattern to search for
         * @param skipCount Number of pattern matches to skip (default: 0)
         *
         * @return SearchResults containing module base, found address, and offset, or std::nullopt
         *
         * @note Module must already be loaded in the current process
         * @note Will log search results if BYTEWEAVER_ENABLE_PATTERN_SCAN_LOGGING is enabled
         *
         * ### Example:
         * ```cpp
         * auto result = ModuleSearch(L"ntdll.dll", "NtCreateFile", "48,8B,C4,48,89,58,08");
         * ```
         */
        static SearchResults ModuleSearch(const std::wstring& moduleName,
                                        const std::string& symbolName,
                                        const std::string& signature,
                                        size_t skipCount = 0);

        /**
         * @brief Searches for a parsed byte pattern within a specific loaded module.
         *
         * Searches for the given pre-parsed pattern within the target module's memory space,
         * providing full search results including module information and offsets.
         *
         * @param moduleName Wide string name of the target module (e.g., L"user32.dll")
         * @param symbolName Descriptive name for logging and identification
         * @param pattern Pre-parsed vector of optional bytes representing the search pattern
         * @param skipCount Number of pattern matches to skip before returning (default: 0)
         *
         * @return SearchResults tuple containing:
         *         - Module base address
         *         - Absolute address where pattern was found
         *         - Offset from module base to found address
         *         Returns std::nullopt if module not found or pattern not located
         *
         * @note More efficient than string version if pattern is reused multiple times
         * @note Automatically handles PE header parsing to determine module size
         *
         * ### Example:
         * ```cpp
         * auto pattern = ParsePattern("FF,25,?,?,?,?");
         * auto result = ModuleSearch(L"user32.dll", "MessageBoxW_Jump", pattern);
         * if (result) {
         *     auto [base, address, offset] = *result;
         *     std::cout << "Found at offset: 0x" << std::hex << offset << std::endl;
         * }
         * ```
         */
        static SearchResults ModuleSearch(const std::wstring& moduleName,
                                        const std::string& symbolName,
                                        const std::vector<std::optional<uint8_t>>& pattern,
                                        size_t skipCount = 0);

        /**
         * @brief Looks up an exported function address from a module's export table.
         *
         * Uses the Windows API to resolve the address of an exported function from
         * the specified module's export table. This is the most reliable method for
         * finding well-known API functions.
         *
         * @param moduleName Wide string name of the module containing the export
         * @param symbolName Name of the exported function/symbol to find
         *
         * @return SearchResults containing module base, export address, and offset, or std::nullopt
         *
         * @note This method only works for functions listed in the module's export table
         * @note Much faster than pattern scanning for exported functions
         * @note Module must be loaded in the current process
         * @note Symbol names are case-sensitive
         *
         * ### Example:
         * ```cpp
         * // Find CreateFileW in kernel32.dll
         * auto result = LookupExportAddress(L"kernel32.dll", "CreateFileW");
         * if (result) {
         *     auto [moduleBase, exportAddr, offset] = *result;
         *     // Use exportAddr for hooking
         * }
         *
         * // This will fail - not an exported symbol
         * auto internal = LookupExportAddress(L"kernel32.dll", "InternalFunction");
         * ```
         */
        static SearchResults LookupExportAddress(const std::wstring& moduleName,
                                               const std::string& symbolName);
    };
}