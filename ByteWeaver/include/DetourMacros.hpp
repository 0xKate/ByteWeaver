// Copyright(C) 2025 0xKate - MIT License

#pragma once

#include <ByteWeaverPCH.h>
#include <WinDetour.h>
#include <MemoryManager.h>

/**
 *  Declare a hook.
 * @param Name The Prefix for the macro, and string name of hook/patch.
 * @param Ret The return type. (ex. int)
 * @param CallType The calling convention of the original function. (ex. __cdecl)
 * @param HookCallType The calling convention of the hook. (ex. __fastcall)
 */
#define DECLARE_HOOK(Name, Ret, CallType, HookCallType, ...)        \
using Name##_t = Ret(CallType*)(__VA_ARGS__);                       \
static inline uintptr_t Name##Address{};                            \
static inline Name##_t  Name##Original{};                           \
static Ret HookCallType Name##Hook(__VA_ARGS__);


/**
 * For hooking methods using __thiscall. Adds THIS, and EDX params for you.
 * @param Name The Prefix for the macro, and string name of hook/patch.
 * @param Ret The return type. (ex. int)
 * @param HookCallType The calling convention of the hook. (ex. __fastcall)
 */
#define DECLARE_HOOK_THISCALL(Name, Ret, HookCallType, ...)         \
using Name##_t = Ret(__thiscall*)(const void* p_this, __VA_ARGS__); \
static inline uintptr_t Name##Address{};                            \
static inline Name##_t  Name##Original{};                           \
static Ret HookCallType Name##Hook(const void* p_this, int edx, __VA_ARGS__);


/**
 *  Install a hook using symbols in AddressDB.
 * @param Name The Prefix for the macro, and string name of hook/patch.
 * @param Symbol The exact function name as it was entered in addressDB. (ex. lua_gettop)
 * @param Module The exact module name in AddressDB. (ex. lua514.dll)
 */
#define INSTALL_HOOK_SYMBOL(Name, Symbol, Module)                   \
{                                                                   \
    if (const auto _sym = AddressDB::Find(Symbol, Module))          \
    {                                                               \
        Name##Address = _sym->GetAddress().value();                 \
        Name##Original = reinterpret_cast<Name##_t>(Name##Address); \
        MemoryManager::CreateDetour(#Name, Name##Address,           \
            &reinterpret_cast<PVOID&>(Name##Original),              \
            reinterpret_cast<void*>(Name##Hook));                   \
                                                                    \
        Logger::Debug("[" #Name "] Resolved %s at " ADDR_FMT,       \
            #Symbol, static_cast<uintptr_t>(Name##Address));        \
                                                                    \
    }                                                               \
    else {                                                          \
        Logger::Error("[" #Name "] Could not find %s in %s",        \
            #Symbol, #Module);                                      \
    }                                                               \
}


/**
 * Install a hook with pre-defined address.
 * @param Name The Prefix for the macro, and string name of hook/patch.
 * @param AddressValue
 */
#define INSTALL_HOOK_ADDRESS(Name, AddressValue)                    \
{                                                                   \
    Name##Address = AddressValue;                                   \
    Name##Original = reinterpret_cast<Name##_t>(Name##Address);     \
    ByteWeaver::MemoryManager::CreateDetour(#Name, Name##Address,   \
        &reinterpret_cast<PVOID&>(Name##Original),                  \
        reinterpret_cast<void*>(Name##Hook));                       \
}

