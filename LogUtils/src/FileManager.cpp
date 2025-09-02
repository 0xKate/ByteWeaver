
#include "Shared.h"
#include "FileManager.h"
#include "Logger.h"



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

int64_t FileManager::GetCurrentPID()
{
#ifdef _WIN32
    return static_cast<int64_t>(GetCurrentProcessId());
#else
    return static_cast<int64_t>(getpid());
#endif
}

void FileManager::DumpPaths()
{
    Logger::info("BasePath: %s\nWEHPath: %s\nLuaPath: %s\n",
        ProcessPath.string().c_str(),
        ProjectPath.string().c_str(),
        LuaHomePath.string().c_str());
}

void FileManager::Initialize(std::string project_dir)
{
    fs::path processPath(GetProcessPath());

    ProcessPath = processPath.parent_path();
    ProjectPath = ProcessPath / project_dir;
    LuaHomePath = ProjectPath / "Lua";

    try {
        fs::create_directories(ProcessPath);
        fs::create_directories(ProjectPath);
        fs::create_directories(LuaHomePath);
    }
    catch (const fs::filesystem_error& e) {
        Logger::error("[FileManager]: %s", e.what());
    }
}

std::string FileManager::ReadFile(const fs::path& path)
{
    std::ifstream file(path, std::ios::in | std::ios::binary);
    if (!file)
        return {};

    return std::string((std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());
}

bool FileManager::WriteFile(const std::string filePath, const std::string data, bool append)
{
    try {
        // Ensure that the parent directory exists
        fs::path pathObj(filePath);
        if (!pathObj.has_parent_path()) {
            Logger::error("Invalid file path, no parent path found.");
            return false;
        }

        fs::path parentDir = pathObj.parent_path();
        if (!fs::exists(parentDir)) {
            fs::create_directories(parentDir);  // Create the directory structure if it doesn't exist
        }

        // Open the file in the appropriate mode: overwrite or append
        std::ios_base::openmode mode = std::ios::binary | std::ios::out;
        if (append) {
            mode |= std::ios::app;
        }

        std::ofstream fileStream(filePath, mode);
        if (!fileStream.is_open()) {
            std::cerr << "Failed to open the file for writing: " << filePath << std::endl;
            return false;
        }

        // Write the full buffer to the file
        fileStream.write(data.data(), data.size());

        if (!fileStream) {
            std::cerr << "Failed to write data to the file: " << filePath << std::endl;
            return false;
        }

        fileStream.close();
        return true;
    }
    catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
        return false;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception occurred: " << e.what() << std::endl;
        return false;
    }
}