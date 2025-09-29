// Copyright(C) 2025 0xKate - MIT License

#pragma once

#include <ByteWeaverPCH.h>
#include <MemoryModification.h>

namespace ByteWeaver {

    /**
     * @brief A memory modification class that implements function detouring/hooking.
     *
     * The Detour class provides functionality to intercept function calls by redirecting
     * execution to a custom detour function while preserving the ability to call the
     * original function. This is commonly used for API hooking, debugging, and runtime
     * function interception.
     *
     * @note This class is final and cannot be inherited from.
     * @see MemoryModification
     */
    class Detour final : public MemoryModification {
    public:
        /**
         * @brief Pointer to store the original function address after detouring.
         *
         * This pointer will be populated with the address of the original function
         * after the detour is applied, allowing the detour function to call back
         * to the original implementation if needed.
         */
        PVOID* OriginalFunction;

        /**
         * @brief Pointer to the detour function that will replace the original.
         *
         * This is the custom function that will be called instead of the original
         * function when the detour is active.
         */
        PVOID  DetourFunction;

        /**
         * @brief Constructs a new Detour object.
         *
         * @param targetAddress The memory address of the function to be detoured
         * @param originalFunction Pointer that will receive the address of the original function
         * @param detourFunction Pointer to the function that will replace the original
         *
         * @note The originalFunction parameter will be modified to point to the original
         *       function after the detour is applied, enabling calls to the original code.
         */
        Detour(uintptr_t targetAddress, PVOID* originalFunction, PVOID detourFunction);

        /**
         * @brief Applies the detour to the target function.
         *
         * This method installs the detour by modifying the target function to redirect
         * execution to the detour function. The original function address is preserved
         * in the OriginalFunction pointer for potential restoration or callback purposes.
         *
         * @return true if the detour was successfully applied, false otherwise
         *
         * @note This operation modifies executable memory and may require appropriate
         *       privileges depending on the target process and memory protection.
         */
        bool Apply() override;

        /**
         * @brief Restores the original function by removing the detour.
         *
         * This method undoes the detour modification, returning the target function
         * to its original state. After restoration, calls to the target address will
         * execute the original function code instead of the detour.
         *
         * @return true if the detour was successfully removed and original function restored,
         *         false otherwise
         *
         * @note The detour must have been previously applied for restoration to succeed.
         */
        bool Restore() override;
    };
}