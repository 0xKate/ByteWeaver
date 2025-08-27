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

	private:
		// Serialize all Sym* calls.
		static std::mutex SymMutex;
		static std::atomic<int> SymRefCount;
		static bool SymLoaded;	
		static std::vector<const char*> TargetModules;

		static bool InitSymbols();
		
	};
}


