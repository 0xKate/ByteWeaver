#pragma once

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>  // For MAX_PATH and Windows API calls
#else
#include <climits>    // For PATH_MAX on Linux/Unix
#include <unistd.h>   // For readlink and getpid
#endif

// STD Lib
#include <string>
#include <filesystem>
#include <vector>
#include <cstdint>
#include <optional>
#include <mutex>
#include <shared_mutex>
#include <map>
#include <iostream>
#include <thread>
#include <sstream>
#include <fstream>
#include <cstdarg>
#include <cstdio>
#include <unordered_map>
#include <utility> 
#include <array>

namespace LogUtils
{
    namespace fs = std::filesystem;
}