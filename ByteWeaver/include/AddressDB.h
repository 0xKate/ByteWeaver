// Copyright(C) 2025 0xKate - MIT License

#pragma once

#include <ByteWeaverPCH.h>
#include <AddressEntry.h>

namespace ByteWeaver {

    /**
     * @brief Thread-safe static database for managing AddressEntry objects.
     *
     * AddressDB provides a centralized, thread-safe repository for storing and managing
     * AddressEntry objects. It uses a composite key system based on symbol name and
     * module name, allowing efficient lookup and management of function addresses across
     * multiple modules.
     *
     * ## Thread Safety
     *
     * The database uses a shared_mutex for thread safety:
     * - Multiple threads can read simultaneously (shared locks)
     * - Write operations are exclusive (unique locks)
     * - Iterator views maintain locks for their lifetime
     *
     * ## Key System
     *
     * Entries are indexed using a composite key of (symbolName, moduleName).
     * This allows the same symbol name to exist in different modules without conflicts.
     *
     * ## Usage Examples
     *
     * ### Adding Entries:
     * ```cpp
     * // Add entry for export resolution
     * AddressDB::Add("CreateFileW", L"kernel32.dll");
     *
     * // Add with known offset
     * AddressDB::AddWithKnownOffset("InternalFunc", L"ntdll.dll", 0x12340);
     *
     * // Add with pattern scanning
     * AddressDB::AddWithScanPattern("GameLoop", L"game.exe", "48,83,EC,28,?,?,?,?");
     * ```
     *
     * ### Finding and Using Entries:
     * ```cpp
     * if (auto* entry = AddressDB::Find("CreateFileW", L"kernel32.dll")) {
     *     if (auto addr = entry->Update()) {
     *         // Use resolved address
     *     }
     * }
     * ```
     *
     * ### Bulk Operations:
     * ```cpp
     * // Update all entries at once
     * AddressDB::UpdateAll();
     *
     * // Verify all entries can be resolved
     * bool allValid = AddressDB::VerifyAll();
     * ```
     *
     * ### Safe Iteration:
     * ```cpp
     * // Read-only iteration (allows concurrent reads)
     * for (const auto& [key, entry] : AddressDB::Iterate()) {
     *     std::cout << entry.SymbolName << " -> " << std::hex << entry.TargetAddress << std::endl;
     * }
     *
     * // Mutable iteration (exclusive access)
     * for (auto& [key, entry] : AddressDB::Mutate()) {
     *     entry.Update(); // Modify entries safely
     * }
     * ```
     *
     * @note This is a static class - cannot be instantiated
     * @note All operations are thread-safe
     * @warning Iterator views hold locks for their entire lifetime
     * @see AddressEntry
     */
    // ReSharper disable once CppInconsistentNaming
    class AddressDB {
    public:
        /**
         * @brief Deleted default constructor - this is a static-only class.
         */
        AddressDB() = delete;

        /**
         * @brief Deleted copy constructor - prevents copying of static class.
         */
        AddressDB(const AddressDB&) = delete;

        /**
         * @brief Deleted assignment operator - prevents assignment of static class.
         */
        AddressDB& operator=(const AddressDB&) = delete;

        /**
         * @brief Composite key type combining symbol name and module name.
         *
         * Used to uniquely identify entries in the database. The combination
         * allows the same symbol name to exist in different modules without conflicts.
         *
         * - First element: Symbol name (std::string)
         * - Second element: Module name (std::wstring)
         */
        using Key = std::pair<std::string, std::wstring>;

        /**
         * @brief RAII wrapper providing thread-safe read-only access to the database.
         *
         * ReadView holds a shared lock for its entire lifetime, allowing multiple
         * concurrent readers while preventing writers from modifying the database.
         * The view automatically releases the lock when destroyed.
         *
         * @note The lock is held for the entire lifetime of the view object
         * @note Multiple ReadView objects can exist simultaneously
         * @note Blocks write operations while any ReadView exists
         *
         * ### Example:
         * ```cpp
         * {
         *     auto view = AddressDB::Iterate();
         *     for (const auto& [key, entry] : view) {
         *         // Safe read access - other readers allowed, writers blocked
         *         std::cout << entry.SymbolName << std::endl;
         *     }
         * } // Lock automatically released here
         * ```
         */
        class ReadView {
        public:
            /**
             * @brief Constructs ReadView and acquires shared lock.
             */
            ReadView() : _Lock(_Mutex) {}

            /**
             * @brief Returns const iterator to beginning of database.
             */
            static auto begin() noexcept { return _Database.cbegin(); }

            /**
             * @brief Returns const iterator to end of database.
             */
            static auto end() noexcept { return _Database.cend(); }

        private:
            std::shared_lock<std::shared_mutex> _Lock{};
        };

        /**
         * @brief Creates a ReadView for safe iteration over the database.
         *
         * @return ReadView object that provides const iterators and maintains a shared lock
         *
         * @note The returned view holds a shared lock until destroyed
         * @note Multiple concurrent reads are allowed
         *
         * ### Example:
         * ```cpp
         * for (const auto& [key, entry] : AddressDB::Iterate()) {
         *     entry.Dump(); // Read-only operations
         * }
         * ```
         */
        static ReadView Iterate() noexcept { return {}; }

        /**
         * @brief RAII wrapper providing thread-safe mutable access to the database.
         *
         * WriteView holds an exclusive lock for its entire lifetime, preventing
         * all other readers and writers from accessing the database. Use this
         * when you need to modify entries during iteration.
         *
         * @note The lock is held for the entire lifetime of the view object
         * @note Only one WriteView can exist at a time
         * @note Blocks all other access (read and write) while active
         *
         * ### Example:
         * ```cpp
         * {
         *     auto view = AddressDB::Mutate();
         *     for (auto& [key, entry] : view) {
         *         // Exclusive access - can modify entries safely
         *         entry.Update();
         *     }
         * } // Lock automatically released here
         * ```
         */
        class WriteView {
        public:
            /**
             * @brief Constructs WriteView and acquires exclusive lock.
             */
            WriteView() : _Lock(_Mutex) {}

            /**
             * @brief Returns mutable iterator to beginning of database.
             */
            static auto begin() noexcept { return _Database.begin(); }

            /**
             * @brief Returns mutable iterator to end of database.
             */
            static auto end()   noexcept { return _Database.end(); }

        private:
            std::unique_lock<std::shared_mutex> _Lock{};
        };

        /**
         * @brief Creates a WriteView for safe mutable iteration over the database.
         *
         * @return WriteView object that provides mutable iterators and maintains an exclusive lock
         *
         * @note The returned view holds an exclusive lock until destroyed
         * @note Blocks all other database access while active
         *
         * ### Example:
         * ```cpp
         * for (auto& [key, entry] : AddressDB::Mutate()) {
         *     entry.SetKnownOffset(newOffset); // Modify entries
         * }
         * ```
         */
        static WriteView Mutate() noexcept { return {}; }

        // ----- Basic add APIs -----

        /**
         * @brief Adds an existing AddressEntry to the database.
         *
         * Uses the entry's SymbolName and ModuleName as the composite key.
         * If an entry with the same key already exists, it will be replaced.
         *
         * @param entry AddressEntry object to add to the database
         *
         * @note Thread-safe operation
         * @note Replaces existing entries with the same key
         *
         * ### Example:
         * ```cpp
         * AddressEntry entry("CreateFileW", L"kernel32.dll");
         * AddressDB::Add(std::move(entry));
         * ```
         */
        static void Add(AddressEntry entry);

        /**
         * @brief Adds a new entry configured for export table resolution.
         *
         * Creates an AddressEntry that will attempt to resolve the address
         * using the module's export table (default behavior).
         *
         * @param symbolName Name of the exported symbol
         * @param moduleName Name of the module containing the export
         *
         * @note Thread-safe operation
         * @note Sets IsSymbolExport = true by default
         *
         * ### Example:
         * ```cpp
         * AddressDB::Add("CreateFileW", L"kernel32.dll");
         * AddressDB::Add("MessageBoxW", L"user32.dll");
         * ```
         */
        static void Add(std::string symbolName, std::wstring moduleName);

        /**
         * @brief Adds a new entry with a pre-resolved absolute address.
         *
         * Creates an AddressEntry where the target address is already known.
         * Useful for addresses resolved through other means or hardcoded values.
         *
         * @param symbolName Descriptive name for the address
         * @param moduleName Module name for context and key generation
         * @param address Pre-resolved absolute memory address
         *
         * @note Thread-safe operation
         * @note No resolution is needed - address is immediately available
         *
         * ### Example:
         * ```cpp
         * AddressDB::AddWithKnownAddress("HardcodedFunc", L"game.exe", 0x140001000);
         * ```
         */
        static void AddWithKnownAddress(std::string symbolName,
                                       std::wstring moduleName,
                                       uintptr_t address);

        /**
         * @brief Adds a new entry that resolves using a known offset from module base.
         *
         * Creates an AddressEntry that calculates the target address as
         * moduleBase + offset. Useful for non-exported functions with known offsets.
         *
         * @param symbolName Descriptive name for the function
         * @param moduleName Module containing the function
         * @param offset Byte offset from module base to target function
         *
         * @note Thread-safe operation
         * @note Address will be calculated when module is loaded
         *
         * ### Example:
         * ```cpp
         * AddressDB::AddWithKnownOffset("InternalFunc", L"ntdll.dll", 0x45680);
         * ```
         */
        static void AddWithKnownOffset(std::string symbolName,
                                      std::wstring moduleName,
                                      uintptr_t offset);

        /**
         * @brief Adds a new entry that resolves using pattern scanning.
         *
         * Creates an AddressEntry that finds the target by searching for a
         * unique byte pattern within the module's memory space.
         *
         * @param symbolName Descriptive name for the function
         * @param moduleName Module to search within
         * @param pattern Comma-separated hex pattern with optional wildcards
         *
         * @note Thread-safe operation
         * @note Pattern scanning can be slow - use specific patterns
         * @note Supports wildcards (? or ??) for flexible matching
         *
         * ### Example:
         * ```cpp
         * AddressDB::AddWithScanPattern("GameLoop", L"game.exe",
         *                              "48,83,EC,28,?,?,?,?,E8");
         * ```
         */
        static void AddWithScanPattern(std::string symbolName,
                                      std::wstring moduleName,
                                      std::string pattern);

        // ----- Lookup -----

        /**
         * @brief Finds an entry in the database by symbol and module name.
         *
         * @param symbolName Name of the symbol to find
         * @param moduleName Name of the module containing the symbol
         *
         * @return Pointer to the AddressEntry if found, nullptr otherwise
         *
         * @note Thread-safe operation
         * @note Returns a non-owning pointer - do not delete
         * @note Pointer remains valid until the entry is removed from database
         *
         * ### Example:
         * ```cpp
         * if (auto* entry = AddressDB::Find("CreateFileW", L"kernel32.dll")) {
         *     if (auto addr = entry->GetAddress()) {
         *         // Use the resolved address
         *     }
         * } else {
         *     std::cerr << "Entry not found" << std::endl;
         * }
         * ```
         */
        static AddressEntry* Find(const std::string& symbolName, const std::wstring& moduleName);

        /**
         * @brief Finds an entry in the database using a composite key.
         *
         * @param key Composite key containing (symbolName, moduleName)
         *
         * @return Pointer to the AddressEntry if found, nullptr otherwise
         *
         * @note Thread-safe operation
         * @note Convenient overload when you already have a Key object
         *
         * ### Example:
         * ```cpp
         * Key key{"CreateFileW", L"kernel32.dll"};
         * if (auto* entry = AddressDB::Find(key)) {
         *     // Use entry
         * }
         * ```
         */
        static AddressEntry* Find(const Key& key);

        // ----- Management -----

        /**
         * @brief Removes an entry from the database by symbol and module name.
         *
         * @param symbolName Name of the symbol to remove
         * @param moduleName Name of the module containing the symbol
         *
         * @return true if the entry was found and removed, false if not found
         *
         * @note Thread-safe operation
         * @note Invalidates any existing pointers to the removed entry
         *
         * ### Example:
         * ```cpp
         * if (AddressDB::Remove("OldFunction", L"legacy.dll")) {
         *     std::cout << "Entry removed successfully" << std::endl;
         * }
         * ```
         */
        static bool Remove(const std::string& symbolName, const std::wstring& moduleName);

        /**
         * @brief Removes an entry from the database using a composite key.
         *
         * @param key Composite key containing (symbolName, moduleName)
         *
         * @return true if the entry was found and removed, false if not found
         *
         * @note Thread-safe operation
         * @note Convenient overload when you already have a Key object
         */
        static bool Remove(const Key& key);

        /**
         * @brief Removes all entries from the database.
         *
         * Clears the entire database, removing all stored AddressEntry objects.
         *
         * @note Thread-safe operation
         * @note Invalidates all existing pointers to entries
         * @note Cannot be undone - use with caution
         *
         * ### Example:
         * ```cpp
         * AddressDB::Clear(); // Database is now empty
         * ```
         */
        static void Clear();

        /**
         * @brief Updates all entries in the database by calling Update() on each.
         *
         * Iterates through all entries and calls their Update() method to resolve
         * addresses. This is useful for batch resolution after modules are loaded.
         *
         * @note Thread-safe operation
         * @note May take time if many entries use pattern scanning
         * @note Logs resolution results for each entry
         *
         * ### Example:
         * ```cpp
         * // After game initialization
         * AddressDB::UpdateAll(); // Resolve all addresses at once
         * ```
         */
        static void UpdateAll();

        // ----- Debug -----

        /**
         * @brief Dumps detailed information about all entries to the debug log.
         *
         * Calls Dump() on every entry in the database, providing comprehensive
         * information about the current state of all stored addresses.
         *
         * @note Thread-safe operation
         * @note Output goes to the ByteWeaver debug logging system
         * @note Useful for troubleshooting and development
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
        static void DumpAll();

        /**
         * @brief Verifies that all entries in the database can be successfully resolved.
         *
         * Calls Verify() on every entry to ensure they can all be resolved.
         * Returns false if any entry fails verification.
         *
         * @return true if all entries can be resolved, false if any fail
         *
         * @note Thread-safe operation
         * @note Does not update cached values in entries
         * @note Performs actual resolution operations (can be expensive)
         * @note Logs errors for any entries that fail verification
         *
         * ### Example:
         * ```cpp
         * if (AddressDB::VerifyAll()) {
         *     std::cout << "All entries are valid" << std::endl;
         *     AddressDB::UpdateAll(); // Safe to update all
         * } else {
         *     std::cerr << "Some entries cannot be resolved" << std::endl;
         *     AddressDB::DumpAll(); // Debug the issues
         * }
         * ```
         */
        static bool VerifyAll();

    private:
        /**
         * @brief Custom hash function for the composite Key type.
         *
         * Combines hashes of both string components using a well-known algorithm
         * that provides good distribution and minimal collision probability.
         *
         * @note Uses FNV-1a inspired mixing for good hash distribution
         */
        struct KeyHash {
            size_t operator()(const Key& k) const noexcept {
                // simple combine of two hashes
                const size_t h1 = std::hash<std::string>{}(k.first);
                const size_t h2 = std::hash<std::wstring>{}(k.second);
                return h1 ^ h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2);
            }
        };

        /**
         * @brief The internal hash map storing all AddressEntry objects.
         *
         * Static member containing the actual database storage.
         */
        static std::unordered_map<Key, AddressEntry, KeyHash> _Database;

        /**
         * @brief Shared mutex providing thread safety for database operations.
         *
         * Allows multiple concurrent readers or a single exclusive writer.
         */
        static std::shared_mutex _Mutex;
    };
}