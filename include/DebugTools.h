// Copyright(C) 2025 0xKate - MIT License

#pragma once

namespace ByteWeaver {
	class DebugTools {       
	public:        
        // --- Symbol Init/Teardown ---
        static bool InvadeProcess;        
        static void SetTargetModules(std::vector<const char*> targetModules);
        static void LoadModuleSymbols();
        static void EnsureSymInit();
		static void ForceCleanupSymbols();
		static void CleanupSymbols();

        // --- Stacktrace ---
        static void PrintStackTrace();

        // --- Return Address debugging ---
        struct ReturnAddressInfo {
            void* returnAddress{};     // Original return address
            HMODULE     moduleHandle{};      // Owning module handle (nullptr if none)
            uintptr_t   moduleBase{};        // Base address of the module
            size_t      offset{};            // VA - base (aka RVA for image-mapped)
            std::string modulePath;          // Full path
            std::string moduleName;          // Short name (file)
            char        section[9]{};        // PE section name (".text", ".pdata", etc.) or ""
            bool        isImageMapped{};     // True if looks like a valid PE image mapping
            bool        valid{};             // True if resolved to a module

            void Dump() const {
                if (valid) {
                    info("[ReturnAddress] %p  module=%s  base=%p  +0x%zx",
                        returnAddress,
                        moduleName.c_str(),
                        reinterpret_cast<void*>(moduleBase),
                        offset);
                    debug("      fullpath=%s", modulePath.c_str());
                }
                else {
                    error("[ReturnAddress] %p  module=(unknown)", returnAddress);
                }
            }
        };
        static DebugTools::ReturnAddressInfo ResolveReturnAddress(const void* addr);

	private:
		// Serialize all Sym* calls.
		static std::mutex SymMutex;
		static std::atomic<int> SymRefCount;
		static bool SymLoaded;	
		static std::vector<const char*> TargetModules;

		static void PrintAddr(void* addr, const char* prefix = nullptr);
		static bool InitSymbols();
		
	};
}


