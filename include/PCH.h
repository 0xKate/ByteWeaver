#pragma once

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>  // For MAX_PATH and Windows API calls
#define MAX_PATH_LENGTH MAX_PATH  // Use Windows MAX_PATH
#else
#include <climits>    // For PATH_MAX on Linux/Unix
#include <unistd.h>   // For readlink and getpid
#define MAX_PATH_LENGTH PATH_MAX  // Use Unix PATH_MAX
#endif
#include <string>
#include <filesystem>
#include <vector>
#include <cstdint>
#include <optional>
#include <mutex>
#include <map>
#include <iostream>
#include <thread>
#include <sstream>
#include <fstream>
#include <TlHelp32.h>
