#include "../include/patreon_auth.h"
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <mutex>
#include <chrono>
#include <map>

// Thread-safe error message storage (local to this file)
static std::mutex error_mutex_local;
static std::string last_error_local;

static void SetError(const std::string& error) {
    std::lock_guard<std::mutex> lock(error_mutex_local);
    last_error_local = error;
}

// Forward declarations - implementations are in platform-specific files
#ifdef _WIN32
bool CalculateSHA256_Windows(const void* data, size_t size, uint8_t* hash_out);
std::string ComputeHMAC_Windows(const std::string& data, const std::string& secret);
#else
bool CalculateSHA256_Linux(const void* data, size_t size, uint8_t* hash_out);
std::string ComputeHMAC_Linux(const std::string& data, const std::string& secret);
#endif

// Logging system
static std::mutex log_mutex;
static PATREON_LogCallback log_callback = nullptr;
static void* log_user_data = nullptr;

static void LogMessage(const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex);
    if (log_callback) {
        log_callback(message.c_str(), log_user_data);
    }
}

// Enhanced rate limiting with per-token and per-HWID tracking
static std::mutex enhanced_rate_limit_mutex;
static std::map<std::string, std::chrono::steady_clock::time_point> token_last_request;
static std::map<std::string, std::chrono::steady_clock::time_point> hwid_last_request;
static std::map<std::string, int> token_request_count;
static std::map<std::string, int> hwid_request_count;

static const int MIN_REQUEST_INTERVAL_MS = 500; // 0.5 second minimum
static const int MAX_REQUESTS_PER_MINUTE = 10;   // Max 10 requests per minute per token/HWID
static const int MAX_REQUESTS_PER_HOUR = 100;     // Max 100 requests per hour per token/HWID

// Enhanced rate limiting check
static bool CheckEnhancedRateLimit(const std::string& token, const std::string& hwid) {
    std::lock_guard<std::mutex> lock(enhanced_rate_limit_mutex);
    
    auto now = std::chrono::steady_clock::now();
    
    // Check per-token rate limit
    auto token_it = token_last_request.find(token);
    if (token_it != token_last_request.end()) {
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - token_it->second).count();
        
        // Too soon since last request
        if (elapsed_ms < MIN_REQUEST_INTERVAL_MS) {
            LogMessage("Rate limit: Token request too soon");
            return false;
        }
        
        // Check requests per minute
        auto count_it = token_request_count.find(token);
        if (count_it != token_request_count.end()) {
            if (elapsed_ms < 60000 && count_it->second >= MAX_REQUESTS_PER_MINUTE) {
                LogMessage("Rate limit: Token exceeded requests per minute");
                return false;
            }
            // Reset counter if minute passed
            if (elapsed_ms >= 60000) {
                count_it->second = 0;
            }
        }
    }
    
    // Check per-HWID rate limit
    if (!hwid.empty()) {
        auto hwid_it = hwid_last_request.find(hwid);
        if (hwid_it != hwid_last_request.end()) {
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - hwid_it->second).count();
            
            if (elapsed_ms < MIN_REQUEST_INTERVAL_MS) {
                LogMessage("Rate limit: HWID request too soon");
                return false;
            }
            
            auto hwid_count_it = hwid_request_count.find(hwid);
            if (hwid_count_it != hwid_request_count.end()) {
                if (elapsed_ms < 3600000 && hwid_count_it->second >= MAX_REQUESTS_PER_HOUR) {
                    LogMessage("Rate limit: HWID exceeded requests per hour");
                    return false;
                }
                if (elapsed_ms >= 3600000) {
                    hwid_count_it->second = 0;
                }
            }
        }
    }
    
    // Update tracking
    token_last_request[token] = now;
    if (!hwid.empty()) {
        hwid_last_request[hwid] = now;
    }
    
    token_request_count[token]++;
    if (!hwid.empty()) {
        hwid_request_count[hwid]++;
    }
    
    // Cleanup old entries (keep map size reasonable)
    if (token_last_request.size() > 1000) {
        auto cutoff = now - std::chrono::hours(1);
        for (auto it = token_last_request.begin(); it != token_last_request.end();) {
            if (it->second < cutoff) {
                std::string key = it->first; // Save key before erasing
                token_last_request.erase(it++);
                token_request_count.erase(key); // Use saved key
            } else {
                ++it;
            }
        }
    }
    
    // Cleanup HWID maps as well
    if (hwid_last_request.size() > 1000) {
        auto cutoff = now - std::chrono::hours(1);
        for (auto it = hwid_last_request.begin(); it != hwid_last_request.end();) {
            if (it->second < cutoff) {
                std::string key = it->first; // Save key before erasing
                hwid_last_request.erase(it++);
                hwid_request_count.erase(key); // Use saved key
            } else {
                ++it;
            }
        }
    }
    
    return true;
}

// HMAC-SHA256 signing for request authentication
static std::string ComputeHMAC(const std::string& data, const std::string& secret) {
#ifdef _WIN32
    return ComputeHMAC_Windows(data, secret);
#else
    return ComputeHMAC_Linux(data, secret);
#endif
}

// Check if token needs refresh (simple check - in production, parse JWT)
static bool TokenNeedsRefresh(const char* access_token) {
    if (!access_token) return true;
    
    // In a real implementation, you would:
    // 1. Decode JWT token
    // 2. Check expiration time
    // 3. Return true if expires within next 5 minutes
    
    // For now, we'll use a simple heuristic: if token is too old in cache
    static std::map<std::string, std::chrono::steady_clock::time_point> token_cache;
    static std::mutex cache_mutex;
    
    std::lock_guard<std::mutex> lock(cache_mutex);
    
    std::string token_str(access_token);
    auto it = token_cache.find(token_str);
    
    if (it == token_cache.end()) {
        // New token, cache it
        token_cache[token_str] = std::chrono::steady_clock::now();
        return false; // Assume valid for now
    }
    
    // Check if token is older than 50 minutes (tokens typically expire in 1 hour)
    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(
        std::chrono::steady_clock::now() - it->second).count();
    
    return elapsed >= 50; // Suggest refresh if older than 50 minutes
}

// Implementation of exported functions
extern "C" {

int PATREON_SignRequest(const char* data, const char* secret, char* signature_buffer, size_t buffer_size) {
    try {
        if (!data || !secret || !signature_buffer || buffer_size < 65) {
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        std::string data_str(data);
        std::string secret_str(secret);
        
        std::string signature = ComputeHMAC(data_str, secret_str);
        
        if (signature.empty()) {
            SetError("Failed to compute HMAC signature");
            return PATREON_ERROR_UNKNOWN;
        }
        
        // Safe copy with guaranteed null terminator
        size_t copy_size = (signature.length() < buffer_size - 1) ? 
                          signature.length() : buffer_size - 1;
#ifdef _WIN32
        strncpy_s(signature_buffer, buffer_size, signature.c_str(), copy_size);
        signature_buffer[copy_size] = '\0'; // Ensure null terminator
#else
        strncpy(signature_buffer, signature.c_str(), copy_size);
        signature_buffer[copy_size] = '\0'; // Guarantee null terminator
#endif
        
        LogMessage("Request signed successfully");
        return PATREON_SUCCESS;
    }
    catch (...) {
        SetError("Exception during request signing");
        return PATREON_ERROR_UNKNOWN;
    }
}

int PATREON_SetLogCallback(PATREON_LogCallback callback, void* user_data) {
    std::lock_guard<std::mutex> lock(log_mutex);
    log_callback = callback;
    log_user_data = user_data;
    return PATREON_SUCCESS;
}

int PATREON_TokenNeedsRefresh(const char* access_token) {
    try {
        if (!access_token) {
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        bool needs_refresh = TokenNeedsRefresh(access_token);
        return needs_refresh ? 1 : 0;
    }
    catch (...) {
        return PATREON_ERROR_UNKNOWN;
    }
}

} // extern "C"

// Export enhanced rate limiting for internal use
namespace SecurityUtils {
    bool CheckEnhancedRateLimit(const std::string& token, const std::string& hwid) {
        return ::CheckEnhancedRateLimit(token, hwid);
    }
    
    void LogMessage(const std::string& message) {
        ::LogMessage(message);
    }
}

