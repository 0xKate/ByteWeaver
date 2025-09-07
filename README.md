# ByteWeaver

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
ByteWeaver is a static .lib ensure your build environment has it downloaded and located within an include directory.

Simply add this to your CmakeLists.txt and replace `YOUR_PROJECT` with your build target.

~~~cmake
# Fetch ByteWeaver (brings Detours too)
include(FetchContent)
FetchContent_Declare(
        ByteWeaver
        GIT_REPOSITORY https://github.com/0xKate/ByteWeaver.git
        GIT_TAG        0.3.21
)
FetchContent_MakeAvailable(ByteWeaver)

target_link_libraries(YOUR_PROJECT PRIVATE
        ByteWeaver::ByteWeaver
        ByteWeaver::DebugTools	# Optional
        ByteWeaver::LogUtils	# Optional
)
~~~

#### Include the main ByteWeaver.h
~~~cpp
#include <ByteWeaver.h>
~~~

<br/>

#### Logs and errors can be routed to your custom logger.
~~~cpp
// ByteWeaver.h
	using LogFunction = void(*)(int level, const char* msg);
	void ByteWeaver::SetLogCallback(LogFunction fn) 

// If you have a logger
	ByteWeaver::SetLogCallback(MyLogger::log);
~~~

<br/>
