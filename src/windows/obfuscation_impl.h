#ifndef OBFUSCATION_WINDOWS_H
#define OBFUSCATION_WINDOWS_H

#include <windows.h>
#include <intrin.h>

// Windows-specific anti-debugging implementation
namespace Obfuscation {
    // Anti-debugging functions for Windows
    bool IsDebuggerPresent_Windows() {
        // Allow disabling anti-debugging for development
        #ifdef PATREON_DISABLE_ANTI_DEBUG
        return false;
        #endif
        
        // Multiple checks for Windows
        if (::IsDebuggerPresent()) return true;
        
        // Timing check - debuggers slow execution
        LARGE_INTEGER start, end, freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        Sleep(1);
        QueryPerformanceCounter(&end);
        double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
        if (elapsed > 0.05) return true; // Debugger detected (relaxed from 0.01s to 0.05s to avoid false positives)
        
        // Check PEB (Process Environment Block) - x64 only
        #ifdef _WIN64
        typedef struct _PEB {
            BOOLEAN InheritedAddressSpace;
            BOOLEAN ReadImageFileExecOptions;
            BOOLEAN BeingDebugged;
        } PEB, *PPEB;
        
        PPEB peb = (PPEB)__readgsqword(0x60);
        if (peb && peb->BeingDebugged) return true;
        #endif
        
        return false;
    }
    
    // Anti-tampering: Simple integrity check for Windows
    bool VerifyIntegrity_Windows() {
        static bool integrity_checked = false;
        if (integrity_checked) return true;
        
        // Simple check: verify that certain memory addresses are executable
        void* func_ptr = reinterpret_cast<void*>(&IsDebuggerPresent_Windows);
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(func_ptr, &mbi, sizeof(mbi))) {
            if (!(mbi.Protect & PAGE_EXECUTE_READWRITE) && 
                !(mbi.Protect & PAGE_EXECUTE_READ)) {
                return false; // Code section was modified
            }
        }
        integrity_checked = true;
        return true;
    }
}

#endif // OBFUSCATION_WINDOWS_H

