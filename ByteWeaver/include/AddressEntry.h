// Copyright(C) 2025 0xKate - MIT License

#pragma once

#include <ByteWeaverPCH.h>

namespace ByteWeaver {

    /**
     * @brief Represents a single address entry with multiple resolution strategies.
     *
     * AddressEntry encapsulates the information and methods needed to resolve a
     * function or symbol address using various strategies. It supports multiple
     * resolution methods and caches results for performance.
     *
     * ## Address Resolution Strategies
     *
     * The class supports four different ways to resolve addresses:
     *
     * 1. **Export Table Lookup** (default): Uses the module's export table
     * 2. **Known Offset**: Uses a pre-calculated offset from module base
     * 3. **Pattern Scanning**: Searches for byte patterns in module memory
     * 4. **Direct Address**: Uses a pre-resolved absolute address
     *
     * ## Usage Examples
     *
     * ### Export Lookup (Default):
     * ```cpp
     * AddressEntry createFile("CreateFileW", L"kernel32.dll");
     * if (auto addr = createFile.Update()) {
     *     // Use *addr for hooking
     * }
     * ```
     *
     * ### Pattern Scanning:
     * ```cpp
     * auto entry = AddressEntry::WithScanPattern("MyFunction", L"game.exe",
     *                                           "48,8B,C4,?,89,58,08");
     * if (auto addr = entry.Update()) {
     *     // Pattern found at *addr
     * }
     * ```
     *
     * ### Known Offset:
     * ```cpp
     * auto entry = AddressEntry::WithKnownOffset("InternalFunc", L"ntdll.dll", 0x12340);
     * auto addr = entry.GetAddress(); // moduleBase + 0x12340
     * ```
     *
     * @note Addresses are cached after first resolution for performance
     * @see AddressScanner
     */
    class AddressEntry {
    public:
        /**
         * @brief The symbolic name of the function or address being resolved.
         *
         * Used for identification, logging, and export table lookups.
         * Should be the exact export name when using export resolution.
         */
        const std::string  SymbolName;

        /**
         * @brief The name of the module containing the target address.
         *
         * Wide string module name (e.g., L"kernel32.dll", L"ntdll.dll").
         * Must match the loaded module name exactly.
         */
        const std::wstring ModuleName;

        /**
         * @brief Flag indicating if this symbol should be resolved via export table.
         *
         * When true (default), the class will attempt to resolve the address
         * using GetProcAddress() on the module's export table. Set to false
         * when using pattern scanning or offset-based resolution.
         */
        bool IsSymbolExport = true;

        /**
         * @brief Optional offset from module base address.
         *
         * When set, the target address will be calculated as moduleBase + offset.
         * Useful for known function offsets or when dealing with non-exported functions.
         * Takes precedence over pattern scanning when both are available.
         */
        std::optional<uintptr_t> KnownOffset;

        /**
         * @brief Optional byte pattern string for signature scanning.
         *
         * Comma-separated hex string with optional wildcards (? or ??).
         * Example: "48,8B,C4,?,89,58,08"
         * Used when the function is not exported and offset is unknown.
         */
        std::optional<std::string> ScanPattern;

        /**
         * @brief Cached base address of the resolved module.
         *
         * Populated after successful address resolution. Contains the
         * base address where the module is loaded in memory.
         */
        uintptr_t ModuleAddress = 0x0;

        /**
         * @brief Cached final resolved address of the target symbol.
         *
         * Contains the absolute memory address of the target function/symbol
         * after successful resolution. Zero indicates unresolved state.
         */
        uintptr_t TargetAddress = 0x0;

        // --- Constructors ---

        /**
         * @brief Constructs an AddressEntry for export table resolution.
         *
         * Creates an entry that will attempt to resolve the address using
         * the module's export table by default (IsSymbolExport = true).
         *
         * @param symbolName Name of the symbol to resolve
         * @param moduleName Name of the module containing the symbol
         *
         * @note Call Update() to actually resolve the address
         *
         * ### Example:
         * ```cpp
         * AddressEntry entry("CreateFileW", L"kernel32.dll");
         * if (auto addr = entry.Update()) {
         *     // Use resolved address
         * }
         * ```
         */
        AddressEntry(std::string symbolName, std::wstring moduleName);

        /**
         * @brief Creates an AddressEntry with a pre-resolved absolute address.
         *
         * Factory method for creating entries where the address is already known.
         * Useful for addresses resolved through other means or hardcoded values.
         *
         * @param symbolName Descriptive name for the address
         * @param moduleName Module name for context/logging
         * @param address Pre-resolved absolute memory address
         *
         * @return AddressEntry with the target address already set
         *
         * @note Sets IsSymbolExport = false since no resolution is needed
         *
         * ### Example:
         * ```cpp
         * auto entry = AddressEntry::WithKnownAddress("MyFunc", L"game.exe", 0x140001000);
         * auto addr = entry.GetAddress(); // Returns 0x140001000
         * ```
         */
        static AddressEntry WithKnownAddress(std::string symbolName, std::wstring moduleName, uintptr_t address);

        /**
         * @brief Creates an AddressEntry that resolves using a known offset.
         *
         * Factory method for creating entries that calculate the target address
         * as moduleBase + offset. Useful for non-exported functions with known
         * relative positions.
         *
         * @param symbolName Descriptive name for the function
         * @param moduleName Module containing the function
         * @param offset Byte offset from module base to target function
         *
         * @return AddressEntry configured for offset-based resolution
         *
         * @note Sets IsSymbolExport = false to prevent export table lookup
         *
         * ### Example:
         * ```cpp
         * auto entry = AddressEntry::WithKnownOffset("InternalFunc", L"ntdll.dll", 0x45680);
         * // Will resolve to ntdll.dll base + 0x45680
         * ```
         */
        static AddressEntry WithKnownOffset(std::string symbolName, std::wstring moduleName, uintptr_t offset);

        /**
         * @brief Creates an AddressEntry that resolves using pattern scanning.
         *
         * Factory method for creating entries that find functions by searching
         * for unique byte patterns in the module's memory space.
         *
         * @param symbolName Descriptive name for the function
         * @param moduleName Module to search within
         * @param pattern Comma-separated hex pattern with optional wildcards
         *
         * @return AddressEntry configured for pattern-based resolution
         *
         * @note Sets IsSymbolExport = false and pre-parses the pattern
         * @note Pattern scanning can be slow - use specific patterns when possible
         *
         * ### Example:
         * ```cpp
         * auto entry = AddressEntry::WithScanPattern("GameLoop", L"game.exe",
         *                                           "48,83,EC,28,?,?,?,?,E8");
         * if (auto addr = entry.Update()) {
         *     // Pattern found at *addr
         * }
         * ```
         */
        static AddressEntry WithScanPattern(std::string symbolName, std::wstring moduleName, const std::string& pattern);

        // --- Setters ---

        /**
         * @brief Sets the cached module base address.
         *
         * @param moduleAddress Base address where the module is loaded
         *
         * @note Usually set automatically during address resolution
         */
        void SetModuleBase(uintptr_t moduleAddress);

        /**
         * @brief Sets the resolved target address directly.
         *
         * @param targetAddress Absolute address of the target symbol
         *
         * @note Usually set automatically during address resolution
         */
        void SetKnownAddress(uintptr_t targetAddress);

        /**
         * @brief Sets or updates the known offset from module base.
         *
         * @param offset Byte offset from module base to target
         *
         * @note Changes the resolution strategy to offset-based
         */
        void SetKnownOffset(uintptr_t offset);

        /**
         * @brief Sets or updates the pattern scanning string.
         *
         * @param pattern Comma-separated hex pattern string
         *
         * @note Automatically parses and caches the pattern bytes
         * @note Changes the resolution strategy to pattern-based
         */
        void SetScanPattern(const std::string& pattern);

        // --- Accessors ---

        /**
         * @brief Updates and resolves the target address using the configured strategy.
         *
         * Attempts to resolve the target address using the appropriate method
         * based on the entry's configuration:
         * 1. Export table lookup (if IsSymbolExport = true)
         * 2. Pattern scanning (if ScanPattern is set)
         * 3. Module base + offset calculation
         * 4. Module name + offset resolution
         *
         * Caches all resolved information (module base, target address, offset)
         * for future use.
         *
         * @return Optional containing the resolved address, or std::nullopt on failure
         *
         * @note This is the primary method for resolving addresses
         * @note Results are cached - subsequent calls return cached values if available
         * @note Logs detailed information when resolution fails
         *
         * ### Example:
         * ```cpp
         * AddressEntry entry("CreateFileW", L"kernel32.dll");
         * if (auto addr = entry.Update()) {
         *     std::cout << "CreateFileW found at: 0x" << std::hex << *addr << std::endl;
         * } else {
         *     std::cerr << "Failed to resolve CreateFileW" << std::endl;
         * }
         * ```
         */
        std::optional<uintptr_t> Update();

        /**
         * @brief Gets the target address without modifying the entry (const version).
         *
         * Returns the cached address if available, otherwise attempts resolution
         * without updating the entry's cached values. Issues warnings when
         * performing expensive operations on non-updated entries.
         *
         * @return Optional containing the target address, or std::nullopt on failure
         *
         * @note Prefer Update() for initial resolution to avoid repeated expensive operations
         * @note May perform pattern scanning or export lookups without caching results
         *
         * ### Example:
         * ```cpp
         * const AddressEntry& entry = getEntry();
         * if (auto addr = entry.GetAddress()) {
         *     // Use address (may trigger warning if not previously updated)
         * }
         * ```
         */
        std::optional<uintptr_t> GetAddress() const;

        /**
         * @brief Gets the target address, updating cached values if necessary.
         *
         * Non-const version that will update cached values during resolution.
         * More efficient than the const version for repeated access.
         *
         * @return Optional containing the target address, or std::nullopt on failure
         *
         * @note Automatically calls Update() internally if needed
         * @note Modifies the entry's cached values
         *
         * ### Example:
         * ```cpp
         * AddressEntry entry("CreateFileW", L"kernel32.dll");
         * if (auto addr = entry.GetAddress()) {
         *     // Address resolved and cached automatically
         * }
         * ```
         */
        std::optional<uintptr_t> GetAddress();

        // --- Debugging ---

        /**
         * @brief Outputs detailed information about the entry for debugging.
         *
         * Prints comprehensive information about the entry including:
         * - Symbol and module names
         * - Module base address
         * - Calculated offset
         * - Final resolved address
         *
         * @note Uses the ByteWeaver Debug() logging system
         * @note Calls GetAddress() to show current resolution status
         *
         * ### Example Output:
         * ```
         * [AddressEntry] --- CreateFileW Dump ---
         * [AddressEntry]  - Module Name   : kernel32.dll
         * [AddressEntry]  - Module Base   : 0x00007FF8AB123000
         * [AddressEntry]  - Offset        : 0x12340
         * [AddressEntry]  - Final Address : 0x00007FF8AB135340
         * ```
         */
        void Dump() const;

        /**
         * @brief Verifies that the entry can be successfully resolved.
         *
         * Performs validation by attempting to resolve the address using
         * the configured strategy and comparing against any cached values.
         * Useful for testing address resolution without side effects.
         *
         * @return true if the entry can be successfully resolved, false otherwise
         *
         * @note Does not update cached values in the entry
         * @note Performs actual resolution operations (can be expensive)
         * @note Logs errors when resolution fails
         *
         * ### Example:
         * ```cpp
         * AddressEntry entry("CreateFileW", L"kernel32.dll");
         * if (entry.Verify()) {
         *     // Safe to call Update() or GetAddress()
         *     auto addr = entry.Update();
         * } else {
         *     std::cerr << "Entry cannot be resolved" << std::endl;
         * }
         * ```
         */
        bool Verify() const;

    private:
        /**
         * @brief Cached parsed scan bytes for pattern matching.
         *
         * Internal storage for the parsed pattern bytes to avoid
         * re-parsing the pattern string on every scan operation.
         * Populated automatically when SetScanPattern() is called.
         */
        std::optional<std::vector<std::optional<uint8_t>>> _ScanBytes;
    };
}