#include "../../include/patreon_auth.h"
#include <sys/mman.h>
#include <unistd.h>
#include <link.h>
#include <dlfcn.h>
#include <elf.h>
#include <openssl/sha.h>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <cstdio>

// Forward declarations
bool CalculateSHA256_Linux(const void* data, size_t size, uint8_t* hash_out);

// Linux implementation of GetFunctionInfo using DWARF/dladdr
bool GetFunctionInfo_Linux(void* func_ptr, void*& start_addr, size_t& func_size) {
    if (!func_ptr) return false;
    
    // Try to use DWARF via dladdr + /proc/self/maps
    Dl_info info;
    if (dladdr(func_ptr, &info)) {
        start_addr = info.dli_saddr;
        
        // Try to get function size from ELF symbol table
        FILE* maps = fopen("/proc/self/maps", "r");
        if (maps) {
            char line[512];
            unsigned long func_addr = reinterpret_cast<unsigned long>(func_ptr);
            
            while (fgets(line, sizeof(line), maps)) {
                unsigned long start, end;
                if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                    if (func_addr >= start && func_addr < end) {
                        // Function is in this memory region
                        // Try to find function end by pattern matching
                        uint8_t* code = static_cast<uint8_t*>(func_ptr);
                        const size_t max_search = std::min(static_cast<size_t>(end - func_addr), static_cast<size_t>(8192));
                        
                        for (size_t i = 0; i < max_search; i++) {
                            if (code[i] == 0xC3 || // RET
                                (code[i] == 0xC2 && i + 2 < max_search)) { // RET imm16
                                func_size = i + (code[i] == 0xC2 ? 3 : 1);
                                fclose(maps);
                                return true;
                            }
                        }
                        
                        // Fallback: use region size
                        func_size = std::min(static_cast<size_t>(end - func_addr), static_cast<size_t>(4096));
                        fclose(maps);
                        return true;
                    }
                }
            }
            fclose(maps);
        }
        
        // Final fallback: pattern matching without maps
        uint8_t* code = static_cast<uint8_t*>(func_ptr);
        for (size_t i = 0; i < 4096; i++) {
            if (code[i] == 0xC3 || (code[i] == 0xC2 && i + 2 < 4096)) {
                func_size = i + (code[i] == 0xC2 ? 3 : 1);
                return true;
            }
        }
        func_size = 256; // Last resort fallback
        return true;
    }
    
    return false;
}

// Linux implementation of IsMemoryWritable
bool IsMemoryWritable_Linux(void* addr) {
    // Linux: Check /proc/self/maps
    FILE* maps = fopen("/proc/self/maps", "r");
    if (maps) {
        char line[256];
        while (fgets(line, sizeof(line), maps)) {
            unsigned long start, end;
            char perms[5];
            if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
                if (reinterpret_cast<unsigned long>(addr) >= start &&
                    reinterpret_cast<unsigned long>(addr) < end) {
                    fclose(maps);
                    return strchr(perms, 'w') != nullptr;
                }
            }
        }
        fclose(maps);
    }
    return false;
}

// Linux implementation of DetectPatchingTools
bool DetectPatchingTools_Linux() {
    // Check for common tools
    FILE* proc = fopen("/proc/self/maps", "r");
    if (proc) {
        char line[512];
        while (fgets(line, sizeof(line), proc)) {
            // Check for suspicious library names
            if (strstr(line, "libpthread") && strstr(line, "x64dbg")) {
                fclose(proc);
                return true;
            }
            if (strstr(line, "gdb") || strstr(line, "lldb")) {
                fclose(proc);
                return true;
            }
        }
        fclose(proc);
    }
    
    // Check environment variables
    if (getenv("LD_PRELOAD")) {
        return true; // Library preloading detected
    }
    
    return false;
}

// Linux implementation of VerifyFunctionNotHooked
bool VerifyFunctionNotHooked_Linux(void* func_ptr) {
    if (!func_ptr) return false;
    
    // Similar checks as Windows
    uint8_t* code = static_cast<uint8_t*>(func_ptr);
    
    // JMP instruction
    if (code[0] == 0xE9 || code[0] == 0xEB) {
        return false;
    }
    
    // CALL instruction
    if (code[0] == 0xE8) {
        return false;
    }
    
    // INT 3 (breakpoint)
    if (code[0] == 0xCC) {
        return false;
    }
    
    return true;
}

