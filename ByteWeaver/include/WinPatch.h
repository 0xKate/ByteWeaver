// Copyright(C) 2025 0xKate - MIT License

#pragma once

#include <ByteWeaverPCH.h>
#include <MemoryModification.h>

namespace ByteWeaver
{
    /**
     * @brief A memory modification class that implements binary patching functionality.
     *
     * The Patch class provides functionality to modify executable code in memory by
     * replacing specific bytes at a target address with custom byte sequences. This
     * is commonly used for runtime code modification, bug fixes, feature enabling,
     * and reverse engineering tasks.
     *
     * @note This class is final and cannot be inherited from.
     * @see MemoryModification
     */
    class Patch final : public MemoryModification {
    public:
        /**
         * @brief The byte sequence that will be written to the target address.
         *
         * This vector contains the raw bytes that will replace the original code
         * at the patch address when the patch is applied. The size of this vector
         * determines how many bytes will be modified.
         */
        std::vector<uint8_t> PatchBytes;

        /**
         * @brief Constructs a new Patch object.
         *
         * @param patchAddress The memory address where the patch will be applied
         * @param patchBytes A vector containing the bytes to write at the target address
         *
         * @note The size of patchBytes determines how many bytes will be modified
         *       at the target address. Ensure the patch bytes are valid for the
         *       target architecture and instruction alignment.
         */
        Patch(uintptr_t patchAddress, std::vector<uint8_t> patchBytes);

        /**
         * @brief Applies the patch by writing the patch bytes to the target address.
         *
         * This method modifies the memory at the target address by overwriting the
         * existing bytes with the contents of PatchBytes. The original bytes are
         * typically preserved internally to enable restoration.
         *
         * @return true if the patch was successfully applied, false otherwise
         *
         * @note This operation modifies executable memory and may require appropriate
         *       memory protection changes and privileges. Applying invalid patches
         *       can cause program crashes or undefined behavior.
         */
        bool Apply() override;

        /**
         * @brief Restores the original bytes by removing the patch.
         *
         * This method undoes the patch modification by restoring the original bytes
         * that were present at the target address before the patch was applied.
         * After restoration, the memory will contain the original code.
         *
         * @return true if the original bytes were successfully restored, false otherwise
         *
         * @note The patch must have been previously applied for restoration to succeed.
         *       The original bytes must have been preserved during the Apply() operation.
         */
        bool Restore() override;
    };
}