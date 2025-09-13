#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>  // For MAX_PATH and Windows API calls

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