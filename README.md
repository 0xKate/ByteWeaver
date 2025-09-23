﻿# ByteWeaver

**ByteWeaver** is a lightweight, high-performance memory patching and function detouring library for Windows. Designed with both 32-bit and 64-bit support, it provides clean abstractions for memory manipulation, runtime patching, and secure detour management.

## ✨ Features

- ✅ x86 and x64 architecture support  
- ✅ Minimal dependencies (uses Windows APIs + Detours)  
- ✅ Safe memory patching and restoration  
- ✅ Function detouring via Microsoft Detours  
- ✅ Robust logging and error handling  
- ✅ Debug/Release mode support with optional logging  
- ✅ Clean C++ interface for integration into DLLs or native applications  

<br/>

## 📦 Getting Started
Simply add this to your CmakeLists.txt and replace `YOUR_PROJECT` with your build target.

~~~cmake
# Fetch ByteWeaver (brings Detours too)
include(FetchContent)
FetchContent_Declare(
        ByteWeaver
        GIT_REPOSITORY https://github.com/0xKate/ByteWeaver.git
        GIT_TAG        0.4.30
)
FetchContent_MakeAvailable(ByteWeaver)

target_link_libraries(YOUR_PROJECT PRIVATE
        ByteWeaver::ByteWeaver
        ByteWeaver::DebugTools	# Optional
        ByteWeaver::LogUtils	# Optional
)
~~~

#### Include the main ByteWeaver.h
~~~c++
#include <ByteWeaver.h>
~~~

#### Logs and errors can be routed to your custom logger.
~~~c++
// ByteWeaver.h
	using LogFunction = void(*)(int level, const char* msg);
	void ByteWeaver::SetLogCallback(LogFunction fn) 

// If you have a logger
	ByteWeaver::SetLogCallback(MyLogger::log);
~~~

#### Use DetourMacros.hpp to quickly setup hooks.
~~~c++
#include <DetourMacros.hpp>

// Example hook of a __cdecl function.
DECLARE_HOOK(SomeFunc1, int, __cdecl, __cdecl, int a, int b, int c);
INSTALL_HOOK_ADDRESS(SomeFunc1, 0x1234);
void MemoryManager::ApplyByKey("SomeFunc1");

// Example hook of a __thiscall method.
DECLARE_HOOK_THISCALL(SomeThisCallFunc1, int, __fastcall, int a, int b, int c);
INSTALL_HOOK_ADDRESS(SomeThisCallFunc1, 0xDEAD);
void MemoryManager::ApplyByKey("SomeThisCallFunc1");

// Example using symbols (funcname, modulename)
DECLARE_HOOK_THISCALL(SomeThisCallFunc1, int, __fastcall, int a, int b, int c);
AddressDB::Add("SomeFunction", L"SomeModule.dll"); // Uses GetProcAddress to find the symbol.
AddressDB::AddWithScanPattern("SomeFunction", L"SomeModule.dll", "E9,00,00,00,00"); // Scan pattern.
AddressDB::AddWithKnownOffset("SomeFunction", L"SomeModule.dll", 0x00001234); // Offset from module base.
AddressDB::AddWithKnownAddress("SomeFunction", L"SomeModule.dll", 0x12345678); // Static address.
INSTALL_HOOK_SYMBOL(SomeThisCallFunc1, "SomeFunction", L"SomeModule.dll");
void MemoryManager::ApplyByKey("SomeThisCallFunc1");
~~~

#### Use MemoryManager to keep track of your patches and hooks!
~~~c++
static void MyPatch()
{
    if (auto realAddr = GetProcAddress(GetModuleHandleA("kernelbase.dll"), "SomeKernelBaseFunc")) {
        MemoryManager::AddPatch("MyPatch", new Patch(reinterpret_cast<uintptr_t>(realAddr), { 0xE9, 0x00, 0x00, 0x00, 0x00 }));
        MemoryManager::ApplyByKey("MyPatch");
    }
}


static void MyModificationsWithinRange()
{
    std::vector<std::string> mods;
    if (MemoryManager::IsLocationModified(address, length, &mods)) {
        for (const auto& key : mods) {
            // Do something with the list of mods.
        }
    }
}
~~~


