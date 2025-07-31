// Copyright(C) 2025 0xKate - MIT License

#pragma once
#include <unordered_map>

namespace ByteWeaver {

    class Offset {
    public:
        std::string name;
        std::wstring moduleName;
        uintptr_t moduleAddress = 0;
        uintptr_t offset = 0;

        Offset() = default;
        Offset(const std::string& name, const std::wstring& moduleName, uintptr_t offset);

        uintptr_t Address() const;
        void Dump() const;
    };

    class OffsetDB {
    public:
        static std::unordered_map<std::string, Offset> offsets;
        static void InitializeModuleBases();
        static void Add(const std::string& name, const std::wstring& moduleName, uintptr_t offset);
        static bool Erase(const std::string& name);
        static const Offset* Get(const std::string& name);
        static void DumpAll();
    };
}