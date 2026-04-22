#include "../include/patreon_auth.h"
#include <string>
#include <vector>
#include <cstring>
#include <mutex>
#include <map>
#include <chrono>
#include <cstdint>
#include <algorithm>

// Forward declarations
extern "C" {
    int PATREON_VerifyMember(const char* access_token, const char* campaign_id, const char* tier_title, const char* tier_id, int timeout_seconds);
    int PATREON_GetMemberInfo(const char* access_token, char* member_info, size_t buffer_size, int timeout_seconds);
}

// Forward declarations - implementations are in platform-specific files
#ifdef _WIN32
bool GetFunctionInfo_Windows(void* func_ptr, void*& start_addr, size_t& func_size);
bool IsMemoryWritable_Windows(void* addr);
bool DetectPatchingTools_Windows();
bool VerifyFunctionNotHooked_Windows(void* func_ptr);
extern bool CalculateSHA256_Windows(const void* data, size_t size, uint8_t* hash_out);
#else
bool GetFunctionInfo_Linux(void* func_ptr, void*& start_addr, size_t& func_size);
bool IsMemoryWritable_Linux(void* addr);
bool DetectPatchingTools_Linux();
bool VerifyFunctionNotHooked_Linux(void* func_ptr);
extern bool CalculateSHA256_Linux(const void* data, size_t size, uint8_t* hash_out);
#endif

// Anti-patching detection
namespace AntiPatching {
    // Forward declaration
    static bool VerifyLibraryIntegrity();
    
    // Expected SHA256 hashes for critical functions (calculated at build time)
    // These are set via CMake during build process
    // Format: 32 bytes (SHA256 hash)
    // Default: zero hash (integrity check will be skipped until hashes are set)
    #ifndef PATREON_VERIFY_MEMBER_HASH
    static const uint8_t EXPECTED_VERIFY_MEMBER_HASH[32] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    #else
    static const uint8_t EXPECTED_VERIFY_MEMBER_HASH[32] = PATREON_VERIFY_MEMBER_HASH;
    #endif
    
    #ifndef PATREON_GET_MEMBER_INFO_HASH
    static const uint8_t EXPECTED_GET_MEMBER_INFO_HASH[32] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    #else
    static const uint8_t EXPECTED_GET_MEMBER_INFO_HASH[32] = PATREON_GET_MEMBER_INFO_HASH;
    #endif
    
    // Calculate SHA256 hash for code section (production-grade)
    static bool CalculateSHA256(const void* data, size_t size, uint8_t* hash_out) {
#ifdef _WIN32
        return CalculateSHA256_Windows(data, size, hash_out);
#else
        return CalculateSHA256_Linux(data, size, hash_out);
#endif
    }
    
    // Get function address and size using PDB/DWARF (production method)
    static bool GetFunctionInfo(void* func_ptr, void*& start_addr, size_t& func_size) {
#ifdef _WIN32
        return GetFunctionInfo_Windows(func_ptr, start_addr, func_size);
#else
        return GetFunctionInfo_Linux(func_ptr, start_addr, func_size);
#endif
    }
    
    // Verify function integrity using SHA256 (production-grade)
    static bool VerifyFunctionIntegrity(void* func_ptr, const uint8_t* expected_hash) {
        if (!func_ptr || !expected_hash) return true; // Skip if not configured
        
        // Check if hash is zero (not configured)
        bool is_zero_hash = true;
        for (int i = 0; i < 32; i++) {
            if (expected_hash[i] != 0) {
                is_zero_hash = false;
                break;
            }
        }
        if (is_zero_hash) return true; // Hash not configured, skip check
        
        void* start_addr = nullptr;
        size_t func_size = 0;
        
        if (!GetFunctionInfo(func_ptr, start_addr, func_size)) {
            return false; // Could not get function info
        }
        
        // Calculate current SHA256 hash
        uint8_t current_hash[32] = {0};
        if (!CalculateSHA256(start_addr, func_size, current_hash)) {
            return false; // Failed to calculate hash
        }
        
        // Compare hashes (constant-time comparison to prevent timing attacks)
        uint8_t diff = 0;
        for (int i = 0; i < 32; i++) {
            diff |= (current_hash[i] ^ expected_hash[i]);
        }
        
        return diff == 0; // Hashes match
    }
    
    // Check if memory region is writable (indicates possible patching)
    static bool IsMemoryWritable(void* addr) {
#ifdef _WIN32
        return IsMemoryWritable_Windows(addr);
#else
        return IsMemoryWritable_Linux(addr);
#endif
    }
    
    // Check for common patching tools/techniques
    static bool DetectPatchingTools() {
#ifdef _WIN32
        return DetectPatchingTools_Windows();
#else
        return DetectPatchingTools_Linux();
#endif
    }
    
    // Verify critical function addresses haven't been hooked
    static bool VerifyFunctionNotHooked(void* func_ptr) {
#ifdef _WIN32
        return VerifyFunctionNotHooked_Windows(func_ptr);
#else
        return VerifyFunctionNotHooked_Linux(func_ptr);
#endif
    }
    
    // Comprehensive anti-patching check
    static bool PerformAntiPatchingCheck() {
        static bool check_performed = false;
        static bool check_result = true;
        static std::mutex check_mutex;
        
        std::lock_guard<std::mutex> lock(check_mutex);
        
        if (check_performed) {
            return check_result;
        }
        
        // 1. Check for patching tools
        if (DetectPatchingTools()) {
            check_result = false;
            check_performed = true;
            return false;
        }
        
        // 2. Verify critical functions aren't hooked
        // Note: In production, you'd verify actual function pointers
        // This is a simplified check
        
        // 3. Check memory protection
        void* test_addr = reinterpret_cast<void*>(PerformAntiPatchingCheck);
        if (IsMemoryWritable(test_addr)) {
            // Code section should not be writable
            check_result = false;
            check_performed = true;
            return false;
        }
        
        // 4. Verify library integrity
        if (!VerifyLibraryIntegrity()) {
            check_result = false;
            check_performed = true;
            return false;
        }
        
        check_performed = true;
        return check_result;
    }
    
    // Verify library integrity (self-check) - production-grade
    static bool VerifyLibraryIntegrity() {
        // Check if critical functions are accessible
        void* verify_func = reinterpret_cast<void*>(PATREON_VerifyMember);
        void* get_info_func = reinterpret_cast<void*>(PATREON_GetMemberInfo);
        
        if (!verify_func || !get_info_func) {
            return false;
        }
        
        // Verify functions aren't hooked
        if (!VerifyFunctionNotHooked(verify_func)) {
            return false;
        }
        
        if (!VerifyFunctionNotHooked(get_info_func)) {
            return false;
        }
        
        // Check memory protection
        if (IsMemoryWritable(verify_func) || IsMemoryWritable(get_info_func)) {
            return false; // Code sections should not be writable
        }
        
        // Verify function integrity using SHA256 hashes (production method)
        if (!VerifyFunctionIntegrity(verify_func, EXPECTED_VERIFY_MEMBER_HASH)) {
            return false; // Function code was modified
        }
        
        if (!VerifyFunctionIntegrity(get_info_func, EXPECTED_GET_MEMBER_INFO_HASH)) {
            return false; // Function code was modified
        }
        
        return true;
    }
}

// Implementation of exported functions
extern "C" {

PATREON_AUTH_API int PATREON_VerifyClientIntegrity() {
    try {
        // Perform comprehensive anti-patching check
        if (!AntiPatching::PerformAntiPatchingCheck()) {
            return 0; // Patching detected
        }
        
        // Verify library integrity
        if (!AntiPatching::VerifyLibraryIntegrity()) {
            return 0; // Integrity check failed
        }
        
        return 1; // All checks passed
    }
    catch (...) {
        return 0; // Exception during check
    }
}

PATREON_AUTH_API int PATREON_IsClientPatched() {
    try {
        // Quick check for patching
        if (!AntiPatching::PerformAntiPatchingCheck()) {
            return 1; // Patched
        }
        
        return 0; // Not patched
    }
    catch (...) {
        return 1; // Assume patched on error
    }
}

} // extern "C"

