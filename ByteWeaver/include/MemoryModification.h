// Copyright(C) 2025 0xKate - MIT License

#pragma once

#ifndef BYTEWEAVER_ENABLE_LOGGING
    #define BYTEWEAVER_ENABLE_LOGGING 0
#endif

#include <ByteWeaverPCH.h>

namespace ByteWeaver
{
    /**
     * @brief Enumeration defining the types of memory modifications supported.
     *
     * This enum is used to categorize different kinds of memory modifications
     * for identification, logging, and management purposes.
     */
    enum class ModType : uint8_t {
        Detour,      ///< Function detouring/hooking modification
        Patch,       ///< Binary patching modification
        Unspecified = 0xFF  ///< Default/unknown modification type
    };

    /**
     * @brief Abstract base class for all memory modification operations.
     *
     * MemoryModification provides a common interface and shared functionality for
     * different types of runtime memory modifications such as function detouring
     * and binary patching. This class cannot be instantiated directly and must
     * be inherited by concrete implementation classes.
     *
     * ## Creating Custom Extensions
     *
     * To create your own memory modification type, inherit from this class and:
     *
     * 1. **Implement pure virtual methods**: Override Apply() and Restore()
     * 2. **Set the modification type**: Assign appropriate ModType in constructor
     * 3. **Handle target address**: Set TargetAddress and Size in your constructor
     * 4. **Preserve original bytes**: Store original memory contents in OriginalBytes
     * 5. **Manage state**: Update IsModified flag appropriately
     *
     * ### Example Custom Extension:
     *
     * ```cpp
     * class MyCustomMod : public MemoryModification {
     * public:
     *     MyCustomMod(uintptr_t address, size_t size) {
     *         TargetAddress = address;
     *         Size = size;
     *         Type = ModType::Unspecified; // or add custom type
     *
     *         // Store original bytes for restoration
     *         OriginalBytes.resize(size);
     *         memcpy(OriginalBytes.data(), (void*)address, size);
     *     }
     *
     *     bool Apply() override {
     *         // Your custom modification logic here
     *         // Set IsModified = true on success
     *         return true;
     *     }
     *
     *     bool Restore() override {
     *         if (!IsModified) return false;
     *         // Restore original bytes
     *         memcpy((void*)TargetAddress, OriginalBytes.data(), Size);
     *         IsModified = false;
     *         return true;
     *     }
     * };
     * ```
     *
     * @note This is an abstract base class and cannot be instantiated directly.
     * @see Detour, Patch
     */
    class MemoryModification
    {
    protected:
        /**
         * @brief Protected default constructor - only derived classes can construct.
         *
         * This constructor is protected to enforce that MemoryModification can only
         * be instantiated through inheritance, maintaining the abstract nature of
         * this base class.
         */
        MemoryModification() = default;

    public:
        /**
         * @brief Virtual destructor to ensure proper cleanup in derived classes.
         *
         * The virtual destructor ensures that when a MemoryModification pointer
         * is deleted, the most derived destructor is called, preventing resource
         * leaks and ensuring proper cleanup.
         */
        virtual ~MemoryModification() = default;

        /**
         * @brief Flag indicating whether the modification is currently applied.
         *
         * This boolean tracks the current state of the modification:
         * - true: The modification has been applied and is active
         * - false: The modification is not applied (original state)
         *
         * Implementations should update this flag in Apply() and Restore() methods.
         */
        bool IsModified = false;

        /**
         * @brief The memory address where the modification will be applied.
         *
         * This holds the target location in memory where the modification operation
         * will take place. Must be set by derived classes during construction.
         */
        uintptr_t TargetAddress = NULL;

        /**
         * @brief Storage for the original bytes at the target address.
         *
         * This vector preserves the original memory contents before modification,
         * enabling restoration to the original state. Derived classes should
         * populate this during construction or before applying modifications.
         */
        std::vector<uint8_t> OriginalBytes{};

        /**
         * @brief The size in bytes of the memory region being modified.
         *
         * Specifies how many bytes at TargetAddress are affected by this
         * modification. Should match the size of OriginalBytes when populated.
         */
        size_t Size = 0;

        /**
         * @brief Optional string identifier for this modification.
         *
         * Can be used for debugging, logging, or management purposes to
         * provide a human-readable name or description for the modification.
         * Not used by the base class but available for derived class use.
         */
        std::string Key{};

        /**
         * @brief Optional group identifier for organizing related modifications.
         *
         * Allows grouping of related modifications for batch operations,
         * management, or organizational purposes. Default value is 0x0000.
         */
        uint16_t GroupID = 0x0000;

        /**
         * @brief The type of memory modification this instance represents.
         *
         * Used to identify the specific kind of modification for logging,
         * debugging, and management. Should be set by derived classes.
         */
        ModType Type = ModType::Unspecified;

        /**
         * @brief Pure virtual method to apply the memory modification.
         *
         * Derived classes must implement this method to perform their specific
         * type of memory modification. The implementation should:
         * - Perform the actual memory modification
         * - Set IsModified = true on success
         * - Handle any necessary memory protection changes
         * - Return success/failure status
         *
         * @return true if the modification was successfully applied, false otherwise
         *
         * @note Implementations should be thread-safe if used in multithreaded contexts
         * @warning Memory modifications can cause crashes if applied incorrectly
         */
        virtual bool Apply() = 0;

        /**
         * @brief Pure virtual method to restore the original memory state.
         *
         * Derived classes must implement this method to undo their memory
         * modifications and restore the original state. The implementation should:
         * - Check if IsModified is true before attempting restoration
         * - Restore original bytes from OriginalBytes
         * - Set IsModified = false on success
         * - Handle any necessary memory protection changes
         * - Return success/failure status
         *
         * @return true if the original state was successfully restored, false otherwise
         *
         * @note Should only succeed if Apply() was previously called successfully
         * @warning Attempting to restore without a prior successful Apply() may fail
         */
        virtual bool Restore() = 0;
    };
}