#pragma once

namespace LogUtils
{
	class FileManager {
	public:
		static fs::path ProcessPath; // Path to the directory, excluding the executable
		static fs::path ProjectPath;  // Path to /WEHTool
		static fs::path LuaHomePath;  // Path to /WEHTool/Lua

		static std::string GetProcessPath();
		static int64_t GetCurrentPid();
		static void Initialize(const std::string& projectDir);
		static void DumpPaths();
		static std::string ReadFile(const fs::path& path);
		static bool WriteFile(const std::string& filePath, const std::string& data, bool append = false);
	};
}

