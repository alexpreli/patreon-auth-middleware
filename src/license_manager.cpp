#include "../include/patreon_auth.h"
#include <string>
#include <map>
#include <mutex>
#include <fstream>
#include <sstream>
#include <chrono>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <regex>

// Safe string copy function (guarantees null terminator)
static void SafeStringCopy(char* dest, size_t dest_size, const std::string& src) {
    if (!dest || dest_size == 0) return;
    
    size_t copy_size = (src.length() < dest_size - 1) ? src.length() : dest_size - 1;
    
#ifdef _WIN32
    strncpy_s(dest, dest_size, src.c_str(), copy_size);
    dest[copy_size] = '\0'; // Ensure null terminator
#else
    strncpy(dest, src.c_str(), copy_size);
    dest[copy_size] = '\0'; // Guarantee null terminator
#endif
}

// Forward declarations - implementations are in platform-specific files
#ifdef _WIN32
std::string GetStoragePath_Windows();
void EnsureDirectoryExists_Windows(const std::string& filepath);
#else
std::string GetStoragePath_Linux();
void EnsureDirectoryExists_Linux(const std::string& filepath);
#endif

// License management
namespace LicenseManager {
    // Policy setting
    static int license_policy = PATREON_LICENSE_POLICY_BLOCK; // Default: block
    static std::mutex policy_mutex;
    
    // License storage: token -> (hwid, registration_time, last_transfer_time)
    struct LicenseInfo {
        std::string hwid;
        std::chrono::steady_clock::time_point registration_time;
        std::chrono::steady_clock::time_point last_transfer_time;
        int transfer_count;
    };
    
    static std::mutex license_mutex;
    static std::map<std::string, LicenseInfo> license_db;
    static const int MAX_TRANSFERS_PER_WEEK = 1;
    static const int TRANSFER_COOLDOWN_DAYS = 7;
    static const size_t MAX_LICENSE_DB_SIZE = 10000; // Maximum number of licenses to store
    
    // Get storage file path
    static std::string GetStoragePath() {
#ifdef _WIN32
        return GetStoragePath_Windows();
#else
        return GetStoragePath_Linux();
#endif
    }
    
    // Ensure directory exists
    static void EnsureDirectoryExists(const std::string& filepath) {
#ifdef _WIN32
        EnsureDirectoryExists_Windows(filepath);
#else
        EnsureDirectoryExists_Linux(filepath);
#endif
    }
    
    // Simple encryption for storage (XOR with key)
    static const unsigned char STORAGE_KEY = 0x7A;
    
    static std::string EncryptStorage(const std::string& data) {
        std::string result;
        result.reserve(data.length());
        for (char c : data) {
            result += static_cast<char>(c ^ STORAGE_KEY);
        }
        return result;
    }
    
    static std::string DecryptStorage(const std::string& data) {
        return EncryptStorage(data); // XOR is symmetric
    }
    
    // Validate token format (basic validation)
    static bool ValidateTokenFormat(const std::string& token) {
        if (token.empty() || token.length() < 10 || token.length() > 2048) {
            return false;
        }
        // Basic check: token should contain alphanumeric characters and some special chars
        // Patreon tokens typically contain alphanumeric and hyphens/underscores
        std::regex token_pattern("^[a-zA-Z0-9_-]+$");
        return std::regex_match(token, token_pattern);
    }
    
    // Load licenses from file
    static void LoadLicenses() {
        std::lock_guard<std::mutex> lock(license_mutex);
        
        std::string filepath = GetStoragePath();
        std::ifstream file(filepath, std::ios::binary);
        
        if (!file.is_open()) {
            return; // No existing licenses
        }
        
        std::string encrypted_data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        file.close();
        
        if (encrypted_data.empty()) {
            return;
        }
        
        std::string data = DecryptStorage(encrypted_data);
        
        // Validate decrypted data format (should contain pipe separators)
        if (data.find('|') == std::string::npos) {
            // Log error: corrupted file
            // Note: We can't use SecurityUtils::LogMessage here as it might cause circular dependency
            // In production, you might want to use a simpler logging mechanism
            return; // Corrupted file
        }
        
        std::istringstream iss(data);
        std::string line;
        size_t line_count = 0;
        size_t error_count = 0;
        
        while (std::getline(iss, line) && license_db.size() < MAX_LICENSE_DB_SIZE) {
            line_count++;
            if (line.empty()) continue;
            
            // Format: token|hwid|reg_time|last_transfer_time|transfer_count
            size_t pos1 = line.find('|');
            if (pos1 == std::string::npos) {
                error_count++;
                continue;
            }
            
            size_t pos2 = line.find('|', pos1 + 1);
            if (pos2 == std::string::npos) {
                error_count++;
                continue;
            }
            
            size_t pos3 = line.find('|', pos2 + 1);
            if (pos3 == std::string::npos) {
                error_count++;
                continue;
            }
            
            size_t pos4 = line.find('|', pos3 + 1);
            if (pos4 == std::string::npos) {
                error_count++;
                continue;
            }
            
            std::string token = line.substr(0, pos1);
            std::string hwid = line.substr(pos1 + 1, pos2 - pos1 - 1);
            
            // Validate token format
            if (!ValidateTokenFormat(token) || hwid.empty()) {
                error_count++;
                continue;
            }
            
            // Safe parsing with exception handling
            try {
                std::string reg_time_str = line.substr(pos2 + 1, pos3 - pos2 - 1);
                std::string last_transfer_str = line.substr(pos3 + 1, pos4 - pos3 - 1);
                std::string transfer_count_str = line.substr(pos4 + 1);
                
                long long reg_time = std::stoll(reg_time_str);
                long long last_transfer = std::stoll(last_transfer_str);
                int transfer_count = std::stoi(transfer_count_str);
                
                // Validate parsed values
                if (transfer_count < 0 || transfer_count > 1000) {
                    error_count++;
                    continue;
                }
                
                LicenseInfo info;
                info.hwid = hwid;
                info.registration_time = std::chrono::steady_clock::time_point(
                    std::chrono::steady_clock::duration(reg_time));
                info.last_transfer_time = std::chrono::steady_clock::time_point(
                    std::chrono::steady_clock::duration(last_transfer));
                info.transfer_count = transfer_count;
                
                license_db[token] = info;
            }
            catch (const std::invalid_argument&) {
                error_count++;
                continue; // Invalid number format
            }
            catch (const std::out_of_range&) {
                error_count++;
                continue; // Number out of range
            }
            catch (...) {
                error_count++;
                continue; // Other parsing errors
            }
        }
        
        // If too many errors, consider file corrupted
        if (line_count > 0 && error_count > line_count / 2) {
            // More than half the lines had errors - file is likely corrupted
            license_db.clear(); // Clear potentially corrupted data
        }
    }
    
    // Save licenses to file
    static void SaveLicenses() {
        std::lock_guard<std::mutex> lock(license_mutex);
        
        // Limit database size before saving
        if (license_db.size() > MAX_LICENSE_DB_SIZE) {
            // Remove oldest entries (by registration time)
            std::vector<std::pair<std::string, std::chrono::steady_clock::time_point>> entries;
            for (const auto& entry : license_db) {
                entries.push_back({entry.first, entry.second.registration_time});
            }
            
            // Sort by registration time (oldest first)
            std::sort(entries.begin(), entries.end(), 
                [](const auto& a, const auto& b) {
                    return a.second < b.second;
                });
            
            // Remove oldest entries
            size_t to_remove = license_db.size() - MAX_LICENSE_DB_SIZE;
            for (size_t i = 0; i < to_remove; i++) {
                license_db.erase(entries[i].first);
            }
        }
        
        std::string filepath = GetStoragePath();
        EnsureDirectoryExists(filepath);
        
        std::ostringstream oss;
        for (const auto& entry : license_db) {
            auto reg_duration = entry.second.registration_time.time_since_epoch();
            auto transfer_duration = entry.second.last_transfer_time.time_since_epoch();
            
            oss << entry.first << "|"
                << entry.second.hwid << "|"
                << reg_duration.count() << "|"
                << transfer_duration.count() << "|"
                << entry.second.transfer_count << "\n";
        }
        
        std::string data = oss.str();
        std::string encrypted = EncryptStorage(data);
        
        std::ofstream file(filepath, std::ios::binary | std::ios::trunc);
        if (file.is_open()) {
            file.write(encrypted.c_str(), encrypted.length());
            file.close();
        }
    }
    
    // Initialize (load on first use)
    static bool initialized = false;
    static void Initialize() {
        if (!initialized) {
            LoadLicenses();
            initialized = true;
        }
    }
    
    // Check if transfer is allowed
    static bool CanTransfer(const LicenseInfo& info) {
        if (info.transfer_count == 0) {
            return true; // First registration
        }
        
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::hours>(
            now - info.last_transfer_time).count();
        
        // Check if cooldown period has passed
        if (elapsed >= (TRANSFER_COOLDOWN_DAYS * 24)) {
            return true;
        }
        
        // Check if transfer count is within limit
        return info.transfer_count < MAX_TRANSFERS_PER_WEEK;
    }
}

// Implementation of exported functions
extern "C" {

int PATREON_SetLicensePolicy(int policy) {
    try {
        std::lock_guard<std::mutex> lock(LicenseManager::policy_mutex);
        
        if (policy == PATREON_LICENSE_POLICY_BLOCK || 
            policy == PATREON_LICENSE_POLICY_TRANSFER) {
            LicenseManager::license_policy = policy;
            return PATREON_SUCCESS;
        }
        
        return PATREON_ERROR_INVALID_INPUT;
    }
    catch (...) {
        return PATREON_ERROR_UNKNOWN;
    }
}

int PATREON_CheckLicenseStatus(const char* access_token) {
    try {
        if (!access_token) {
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        // Validate token format
        std::string token_str(access_token);
        if (!LicenseManager::ValidateTokenFormat(token_str)) {
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        LicenseManager::Initialize();
        
        // Get current HWID
        char current_hwid[256] = {0};
        size_t hwid_len = PATREON_GetHardwareID(current_hwid, sizeof(current_hwid));
        if (hwid_len == 0) {
            return PATREON_ERROR_UNKNOWN;
        }
        
        std::string current_hwid_str(current_hwid);
        
        std::lock_guard<std::mutex> lock(LicenseManager::license_mutex);
        
        auto it = LicenseManager::license_db.find(token_str);
        
        if (it == LicenseManager::license_db.end()) {
            // No license registered - new device
            return PATREON_LICENSE_STATUS_NEW;
        }
        
        // Check if HWID matches
        if (it->second.hwid == current_hwid_str) {
            return PATREON_LICENSE_STATUS_VALID;
        }
        
        // HWID mismatch
        return PATREON_LICENSE_STATUS_MISMATCH;
    }
    catch (...) {
        return PATREON_ERROR_UNKNOWN;
    }
}

int PATREON_RegisterOrTransferLicense(const char* access_token, int force_transfer) {
    try {
        if (!access_token) {
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        // Validate token format
        std::string token_str(access_token);
        if (!LicenseManager::ValidateTokenFormat(token_str)) {
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        LicenseManager::Initialize();
        
        // Get current HWID
        char current_hwid[256] = {0};
        size_t hwid_len = PATREON_GetHardwareID(current_hwid, sizeof(current_hwid));
        if (hwid_len == 0) {
            return PATREON_ERROR_UNKNOWN;
        }
        
        std::string current_hwid_str(current_hwid);
        
        std::lock_guard<std::mutex> lock(LicenseManager::license_mutex);
        
        // Check database size limit
        if (LicenseManager::license_db.size() >= LicenseManager::MAX_LICENSE_DB_SIZE) {
            // Try to remove oldest entry if at limit
            if (!force_transfer) {
                // Find oldest entry
                auto oldest_it = LicenseManager::license_db.begin();
                auto oldest_time = oldest_it->second.registration_time;
                for (auto it = LicenseManager::license_db.begin(); 
                     it != LicenseManager::license_db.end(); ++it) {
                    if (it->second.registration_time < oldest_time) {
                        oldest_time = it->second.registration_time;
                        oldest_it = it;
                    }
                }
                LicenseManager::license_db.erase(oldest_it);
            }
        }
        
        auto it = LicenseManager::license_db.find(token_str);
        auto now = std::chrono::steady_clock::now();
        
        if (it == LicenseManager::license_db.end()) {
            // New registration
            LicenseManager::LicenseInfo info;
            info.hwid = current_hwid_str;
            info.registration_time = now;
            info.last_transfer_time = now;
            info.transfer_count = 0;
            
            LicenseManager::license_db[token_str] = info;
            LicenseManager::SaveLicenses();
            
            return PATREON_SUCCESS;
        }
        
        // Check if already registered on this device
        if (it->second.hwid == current_hwid_str) {
            return PATREON_SUCCESS; // Already registered
        }
        
        // Transfer to new device
        if (!force_transfer && !LicenseManager::CanTransfer(it->second)) {
            return PATREON_LICENSE_STATUS_TRANSFER_LIMIT;
        }
        
        // Perform transfer
        it->second.hwid = current_hwid_str;
        it->second.last_transfer_time = now;
        it->second.transfer_count++;
        
        LicenseManager::SaveLicenses();
        
        return PATREON_SUCCESS;
    }
    catch (...) {
        return PATREON_ERROR_UNKNOWN;
    }
}

size_t PATREON_GetRegisteredHWID(const char* access_token, char* hwid_buffer, size_t buffer_size) {
    try {
        if (!access_token || !hwid_buffer || buffer_size == 0) {
            return 0;
        }
        
        // Validate buffer size (must be at least 1 for null terminator)
        if (buffer_size < 1) {
            return 0;
        }
        
        LicenseManager::Initialize();
        
        std::string token_str(access_token);
        
        std::lock_guard<std::mutex> lock(LicenseManager::license_mutex);
        
        auto it = LicenseManager::license_db.find(token_str);
        if (it == LicenseManager::license_db.end()) {
            return 0; // Not found
        }
        
        // Use SafeStringCopy for safe copying
        SafeStringCopy(hwid_buffer, buffer_size, it->second.hwid);
        
        size_t copy_size = (it->second.hwid.length() < buffer_size - 1) ?
                          it->second.hwid.length() : buffer_size - 1;
        
        return copy_size;
    }
    catch (...) {
        return 0;
    }
}

int PATREON_VerifyMemberWithLicense(const char* access_token, const char* campaign_id, const char* tier_title, const char* tier_id, int timeout_seconds) {
    try {
        if (!access_token) {
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        // Validate token format first
        std::string token_str(access_token);
        if (!LicenseManager::ValidateTokenFormat(token_str)) {
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        // OPTIMIZATION: Check license status FIRST (before Patreon API call)
        // This avoids unnecessary API calls if license is already blocked
        int license_status = PATREON_CheckLicenseStatus(access_token);
        
        std::lock_guard<std::mutex> policy_lock(LicenseManager::policy_mutex);
        int policy = LicenseManager::license_policy;
        
        // If policy is BLOCK and license is mismatched, fail early
        if (license_status == PATREON_LICENSE_STATUS_MISMATCH && 
            policy == PATREON_LICENSE_POLICY_BLOCK) {
            return PATREON_ERROR_NOT_MEMBER; // Block access without API call
        }
        
        // Now verify with Patreon API
        int patreon_result = PATREON_VerifyMember(access_token, campaign_id, tier_title, tier_id, timeout_seconds);
        if (patreon_result != PATREON_SUCCESS) {
            return patreon_result; // Patreon verification failed
        }
        
        // Handle license status with thread-safe access
        switch (license_status) {
        case PATREON_LICENSE_STATUS_NEW:
            // New device - register automatically if policy allows
            if (policy == PATREON_LICENSE_POLICY_TRANSFER) {
                if (PATREON_RegisterOrTransferLicense(access_token, 0) == PATREON_SUCCESS) {
                    return PATREON_SUCCESS;
                }
            } else {
                // Policy is BLOCK, but this is a new device, so allow registration
                if (PATREON_RegisterOrTransferLicense(access_token, 0) == PATREON_SUCCESS) {
                    return PATREON_SUCCESS;
                }
            }
            return PATREON_ERROR_UNKNOWN;
            
        case PATREON_LICENSE_STATUS_VALID:
            // HWID matches - access granted
            return PATREON_SUCCESS;
            
        case PATREON_LICENSE_STATUS_MISMATCH:
            // HWID doesn't match
            if (policy == PATREON_LICENSE_POLICY_BLOCK) {
                // Block access (shouldn't reach here due to early check, but keep for safety)
                return PATREON_ERROR_NOT_MEMBER;
            } else if (policy == PATREON_LICENSE_POLICY_TRANSFER) {
                // Try to transfer
                int transfer_result = PATREON_RegisterOrTransferLicense(access_token, 0);
                if (transfer_result == PATREON_SUCCESS) {
                    return PATREON_SUCCESS; // Transfer successful
                } else if (transfer_result == PATREON_LICENSE_STATUS_TRANSFER_LIMIT) {
                    return PATREON_ERROR_NOT_MEMBER; // Transfer limit exceeded
                }
                return transfer_result;
            }
            return PATREON_ERROR_NOT_MEMBER;
            
        default:
            return PATREON_ERROR_UNKNOWN;
        }
    }
    catch (...) {
        return PATREON_ERROR_UNKNOWN;
    }
}

} // extern "C"

