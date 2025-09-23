
#include "LogUtils.h"
#include "FileManager.h"
#include "Logger.h"

namespace LogUtils
{
    // Define static members
    fs::path FileManager::ProcessPath;
    fs::path FileManager::ProjectPath;
    fs::path FileManager::LuaHomePath;

    std::string FileManager::GetProcessPath()
    {
        char result[MAX_PATH];

    #ifdef _WIN32
        if (GetModuleFileNameA(nullptr, result, MAX_PATH) == 0) {
            throw std::runtime_error("Failed to get process path");
        }
    #else
        ssize_t count = readlink("/proc/self/exe", result, MAX_PATH_LENGTH);
        if (count == -1) {
            throw std::runtime_error("Failed to get process path");
        }
        result[count] = '\0';
    #endif

        return {result};
    }

    int64_t FileManager::GetCurrentPid()
    {
    #ifdef _WIN32
        return GetCurrentProcessId();
    #else
        return static_cast<int64_t>(getpid());
    #endif
    }

    void FileManager::DumpPaths()
    {
        Logger::Info("BasePath: %s\nWEHPath: %s\nLuaPath: %s\n",
            ProcessPath.string().c_str(),
            ProjectPath.string().c_str(),
            LuaHomePath.string().c_str());
    }

    void FileManager::Initialize(const std::string& projectDir)
    {
        const fs::path processPath(GetProcessPath());

        ProcessPath = processPath.parent_path();
        ProjectPath = ProcessPath / projectDir;
        LuaHomePath = ProjectPath / "Lua";

        try {
            fs::create_directories(ProcessPath);
            fs::create_directories(ProjectPath);
            fs::create_directories(LuaHomePath);
        }
        catch (const fs::filesystem_error& e) {
            Logger::Error("[FileManager]: %s", e.what());
        }
    }

    std::string FileManager::ReadFile(const fs::path& path)
    {
        std::ifstream file(path, std::ios::in | std::ios::binary);
        if (!file)
            return {};

        return std::string(std::istreambuf_iterator(file),
            std::istreambuf_iterator<char>());
    }

    bool FileManager::WriteFile(const std::string& filePath, const std::string& data, const bool append)
    {
        try {
            // Ensure that the parent directory exists
            const fs::path pathObj(filePath);
            if (!pathObj.has_parent_path()) {
                Logger::Error("Invalid file path, no parent path found.");
                return false;
            }

            if (const fs::path parentDir = pathObj.parent_path(); !fs::exists(parentDir)) {
                fs::create_directories(parentDir);  // Create the directory structure if it doesn't exist
            }

            // Open the file in the appropriate mode: overwrite or append
            std::ios_base::openmode mode = std::ios::binary | std::ios::out;
            if (append) {
                mode |= std::ios::app;
            }

            std::ofstream fileStream(filePath, mode);
            if (!fileStream.is_open()) {
                Logger::Error("Failed to open the file for writing: %s", filePath.c_str());
                return false;
            }

            // Write the full buffer to the file
            fileStream.write(data.data(), data.size());

            if (!fileStream) {
                Logger::Error("Failed to write data to the file %s", filePath.c_str());
                return false;
            }

            fileStream.close();
            return true;
        }
        catch (const fs::filesystem_error& e) {
            Logger::Error("[FileManager] Filesystem error: %s", e.what());
            return false;
        }
        catch (const std::exception& e) {
            Logger::Error("[FileManager] Exception occurred: %s", e.what());
            return false;
        }
    }

    bool FileManager::FileExists(const fs::path& path)
    {
        try {
            // Check if the path exists and is a regular file (not a directory)
            return fs::exists(path) && fs::is_regular_file(path);
        }
        catch (const fs::filesystem_error& e) {
            Logger::Warn("[FileManager] Error checking if file exists: %s", e.what());
            return false;
        }
    }
}
