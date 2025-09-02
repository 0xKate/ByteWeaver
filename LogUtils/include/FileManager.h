#pragma once

class FileManager {
public:
	static fs::path ProcessPath; // Path to the directory, excluding the executable
	static fs::path ProjectPath;  // Path to /WEHTool
	static fs::path LuaHomePath;  // Path to /WEHTool/Lua

	static std::string GetProcessPath();
	static int64_t GetCurrentPID();
	static void Initialize(std::string project_dir);
	static void DumpPaths();
	static std::string ReadFile(const fs::path& path);
	static bool WriteFile(std::string filePath, std::string data, bool append = false);
};