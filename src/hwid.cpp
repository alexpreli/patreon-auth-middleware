#include "../include/patreon_auth.h"
#include <string>
#include <cstring>
#include <mutex>

// Forward declarations - implementations are in platform-specific files
#ifdef _WIN32
std::string GenerateHWID_Windows();
#else
std::string GenerateHWID_Linux();
#endif

// Generate Hardware ID (HWID) - unique identifier for the machine
static std::string GenerateHWID() {
#ifdef _WIN32
    return GenerateHWID_Windows();
#else
    return GenerateHWID_Linux();
#endif
}

// Get cached or generate new HWID
extern "C" {

PATREON_AUTH_API size_t PATREON_GetHardwareID(char* hwid_buffer, size_t buffer_size) {
    if (!hwid_buffer || buffer_size == 0) {
        return 0;
    }
    
    try {
        static std::string cached_hwid;
        static std::mutex hwid_mutex;
        
        std::lock_guard<std::mutex> lock(hwid_mutex);
        
        if (cached_hwid.empty()) {
            cached_hwid = GenerateHWID();
        }
        
        size_t copy_size = (cached_hwid.length() < buffer_size - 1) ? 
                          cached_hwid.length() : buffer_size - 1;
        
        strncpy(hwid_buffer, cached_hwid.c_str(), copy_size);
        hwid_buffer[copy_size] = '\0';
        
        return copy_size;
    }
    catch (...) {
        return 0;
    }
}

} // extern "C"

