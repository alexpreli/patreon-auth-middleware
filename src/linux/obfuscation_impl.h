#ifndef OBFUSCATION_LINUX_H
#define OBFUSCATION_LINUX_H

#include <sys/ptrace.h>
#include <unistd.h>
#include <time.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// Linux-specific anti-debugging implementation
namespace Obfuscation {
    // Anti-debugging functions for Linux
    bool IsDebuggerPresent_Linux() {
        // Allow disabling anti-debugging for development
        #ifdef PATREON_DISABLE_ANTI_DEBUG
        return false;
        #endif
        
        // Linux anti-debugging
        if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) return true;
        
        // Check /proc/self/status for TracerPid
        FILE* status = fopen("/proc/self/status", "r");
        if (status) {
            char line[256];
            while (fgets(line, sizeof(line), status)) {
                if (strncmp(line, "TracerPid:", 10) == 0) {
                    int pid = atoi(line + 10);
                    fclose(status);
                    return pid != 0;
                }
            }
            fclose(status);
        }
        
        // Timing check
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        usleep(1000); // 1ms
        clock_gettime(CLOCK_MONOTONIC, &end);
        double elapsed = (end.tv_sec - start.tv_sec) * 1000.0 + 
                        (end.tv_nsec - start.tv_nsec) / 1000000.0;
        if (elapsed > 5.0) return true; // Debugger slows execution
        
        return false;
    }
    
    // Anti-tampering: Simple integrity check for Linux
    bool VerifyIntegrity_Linux() {
        static bool integrity_checked = false;
        if (integrity_checked) return true;
        
        // For Linux, we rely on other checks
        (void)integrity_checked; // Suppress unused warning
        integrity_checked = true;
        return true;
    }
}

#endif // OBFUSCATION_LINUX_H

