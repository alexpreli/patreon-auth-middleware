#include "../../include/patreon_auth.h"
#include <windows.h>
#include <winnt.h>
#include <psapi.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <cstring>
#include <cstdint>
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")

// Forward declarations
bool CalculateSHA256_Windows(const void* data, size_t size, uint8_t* hash_out);

// Windows implementation of GetFunctionInfo using PDB
bool GetFunctionInfo_Windows(void* func_ptr, void*& start_addr, size_t& func_size) {
    if (!func_ptr) return false;
    
    start_addr = func_ptr;
    
    // Try to use PDB via DbgHelp API (production method)
    static bool dbghelp_initialized = false;
    static bool dbghelp_available = false;
    
    if (!dbghelp_initialized) {
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
        HANDLE hProcess = GetCurrentProcess();
        dbghelp_available = SymInitialize(hProcess, nullptr, TRUE) != FALSE;
        dbghelp_initialized = true;
    }
    
    if (dbghelp_available) {
        HANDLE hProcess = GetCurrentProcess();
        char symbol_buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char)];
        PSYMBOL_INFO symbol_info = (PSYMBOL_INFO)symbol_buffer;
        symbol_info->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol_info->MaxNameLen = MAX_SYM_NAME;
        
        DWORD64 displacement = 0;
        if (SymFromAddr(hProcess, reinterpret_cast<DWORD64>(func_ptr), &displacement, symbol_info)) {
            // Try to get function size from symbol info
            if (symbol_info->Size > 0 && symbol_info->Size < 65536) {
                func_size = symbol_info->Size;
                return true;
            }
        }
    }
    
    // Fallback: Use VirtualQuery + pattern matching
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(func_ptr, &mbi, sizeof(mbi))) {
        start_addr = mbi.BaseAddress;
        
        // Improved pattern matching for function end detection
        uint8_t* code = static_cast<uint8_t*>(func_ptr);
        const size_t max_search = 8192;
        
        for (size_t i = 0; i < max_search; i++) {
            // Look for RET instruction (0xC3)
            if (code[i] == 0xC3) {
                // Check for common function epilogue patterns
                if (i >= 2 && code[i-1] == 0x5D && code[i-2] == 0x5B) {
                    // POP EBP; POP EBX; RET pattern
                    func_size = i + 1;
                    return true;
                }
                if (i >= 1 && code[i-1] == 0x5D) {
                    // POP EBP; RET pattern
                    func_size = i + 1;
                    return true;
                }
                // Simple RET
                func_size = i + 1;
                return true;
            }
            // RET imm16 (0xC2)
            if (code[i] == 0xC2 && i + 2 < max_search) {
                func_size = i + 3;
                return true;
            }
        }
        
        // If pattern matching fails, use memory region size as fallback
        size_t region_size = static_cast<size_t>(mbi.RegionSize);
        func_size = (region_size < 4096) ? region_size : 4096;
        return true;
    }
    
    return false;
}

// Windows implementation of IsMemoryWritable
bool IsMemoryWritable_Windows(void* addr) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        return (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
               (mbi.Protect & PAGE_READWRITE) ||
               (mbi.Protect & PAGE_WRITECOPY);
    }
    return false;
}

// Windows implementation of DetectPatchingTools
bool DetectPatchingTools_Windows() {
    // Check for common debugging/patching tools
    const char* suspicious_processes[] = {
        "x64dbg.exe",
        "x32dbg.exe",
        "ollydbg.exe",
        "ida.exe",
        "ida64.exe",
        "idaq.exe",
        "idaq64.exe",
        "cheatengine.exe",
        "artmoney.exe",
        "processhacker.exe",
        "hacker.exe"
    };
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                for (const char* proc : suspicious_processes) {
                    if (_stricmp(pe32.szExeFile, proc) == 0) {
                        CloseHandle(hSnapshot);
                        return true; // Suspicious tool detected
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    
    return false;
}

// Windows implementation of VerifyFunctionNotHooked
bool VerifyFunctionNotHooked_Windows(void* func_ptr) {
    if (!func_ptr) return false;
    
    // Check first few bytes for common hook patterns
    uint8_t* code = static_cast<uint8_t*>(func_ptr);
    
    // JMP instruction (0xE9 or 0xEB) - common hook pattern
    if (code[0] == 0xE9 || code[0] == 0xEB) {
        return false; // Function appears to be hooked
    }
    
    // CALL instruction (0xE8) - another hook pattern
    if (code[0] == 0xE8) {
        return false;
    }
    
    // Check for INT 3 (0xCC) - breakpoint
    if (code[0] == 0xCC) {
        return false; // Breakpoint detected
    }
    
    return true;
}

