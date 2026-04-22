#include "../include/patreon_auth.h"
#include "obfuscation.h"
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <map>
#include <chrono>
#include <climits>
#include <algorithm>
#include <cctype>
#include <ctime>

#ifdef _WIN32
#include <time.h>
#endif

// Forward declarations from security_utils.cpp
namespace SecurityUtils {
    bool CheckEnhancedRateLimit(const std::string& token, const std::string& hwid);
    void LogMessage(const std::string& message);
}

#include "http_response.h"

// Forward declarations - implementations are in platform-specific files
#ifdef _WIN32
HttpResponse MakePatreonRequest_Windows(const std::string& url, const std::string& access_token, int timeout_seconds);
HttpResponse MakeServerRequest_Windows(const std::string& url, const std::string& post_data, int timeout_seconds);
int OpenBrowser_Windows(const std::string& url);
#else
HttpResponse MakePatreonRequest_Linux(const std::string& url, const std::string& access_token, int timeout_seconds);
HttpResponse MakeServerRequest_Linux(const std::string& url, const std::string& post_data, int timeout_seconds);
int OpenBrowser_Linux(const std::string& url);
#endif

// Thread-safe error message storage
static std::mutex error_mutex;
static std::string last_error;

// Rate limiting storage
static std::mutex rate_limit_mutex;
static std::map<std::string, std::chrono::steady_clock::time_point> last_request;
static const int MIN_REQUEST_INTERVAL_MS = 500; // 0.5 second between requests per token

// Server URL storage (for OAuth2 and optional API routing)
static std::mutex server_url_mutex;
static std::string server_url; // Empty = use direct Patreon API

// Helper function to set error message (visible to platform-specific files)
void SetError(const std::string& error) {
    std::lock_guard<std::mutex> lock(error_mutex);
    last_error = error;
}

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

// Safe string to integer conversion with overflow checking
static bool SafeStringToInt(const char* str, int& value) {
    if (!str) return false;
    
    char* end_ptr = nullptr;
    long long_val = strtol(str, &end_ptr, 10);
    
    // Check for conversion errors and overflow
    if (end_ptr == str || *end_ptr != '\0') return false;
    if (long_val < INT_MIN || long_val > INT_MAX) return false;
    
    value = static_cast<int>(long_val);
    return true;
}

// Rate limiting check to prevent DoS attacks
static bool CheckRateLimit(const std::string& token) {
    std::lock_guard<std::mutex> lock(rate_limit_mutex);
    
    auto now = std::chrono::steady_clock::now();
    auto it = last_request.find(token);
    
    if (it != last_request.end()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - it->second).count();
        if (elapsed < MIN_REQUEST_INTERVAL_MS) {
            return false; // Too soon, rate limit exceeded
        }
    }
    
    last_request[token] = now;
    
    // Clean up old entries (keep map size reasonable)
    if (last_request.size() > 1000) {
        auto cutoff = now - std::chrono::minutes(5);
        for (auto it = last_request.begin(); it != last_request.end();) {
            if (it->second < cutoff) {
                it = last_request.erase(it);
            } else {
                ++it;
            }
        }
    }
    
    return true;
}

// Validate that response is from Patreon API (not a proxy/local attack) - visible to platform-specific files
bool ValidatePatreonResponse(const std::string& response_data) {
    if (response_data.empty()) {
        return false;
    }
    
    // Check for Patreon API response structure
    // Patreon API v2 responses should contain "data" or "included" fields
    bool has_data = response_data.find("\"data\"") != std::string::npos;
    bool has_included = response_data.find("\"included\"") != std::string::npos;
    bool has_type = response_data.find("\"type\"") != std::string::npos;
    
    // Valid Patreon response should have at least one of these
    if (!has_data && !has_included) {
        return false;
    }
    
    // Check for valid JSON structure (should start with { or [)
    if (response_data.find_first_of("{[") == std::string::npos) {
        return false;
    }
    
    // Additional validation: check for Patreon-specific fields
    bool has_patreon_fields = response_data.find("patreon") != std::string::npos ||
                              response_data.find("member") != std::string::npos ||
                              response_data.find("tier") != std::string::npos ||
                              response_data.find("campaign") != std::string::npos;
    
    // If it looks like JSON but has no Patreon fields, might be fake
    if (has_data && !has_patreon_fields && response_data.length() > 100) {
        return false;
    }
    
    return true;
}

// Validate hostname to prevent MITM attacks - visible to platform-specific files
bool ValidateHostname(const std::string& hostname) {
    // Only allow official Patreon domains
    const std::string allowed_hosts[] = {
        "www.patreon.com",
        "patreon.com",
        "api.patreon.com"
    };
    
    for (const auto& allowed : allowed_hosts) {
        if (hostname == allowed || hostname.find("." + allowed) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

#include "http_response.h"

// Simple JSON parser helper functions
namespace JsonHelper {
    bool GetStringValue(const std::string& json, const std::string& key, std::string& value) {
        std::string search_key = "\"" + key + "\"";
        size_t pos = json.find(search_key);
        if (pos == std::string::npos) return false;
        
        pos = json.find(":", pos);
        if (pos == std::string::npos) return false;
        
        pos = json.find_first_of("\"", pos);
        if (pos == std::string::npos) return false;
        pos++; // Skip opening quote
        
        size_t end_pos = json.find("\"", pos);
        if (end_pos == std::string::npos) return false;
        
        value = json.substr(pos, end_pos - pos);
        return true;
    }
    
    bool GetBoolValue(const std::string& json, const std::string& key, bool& value) {
        std::string search_key = "\"" + key + "\"";
        size_t pos = json.find(search_key);
        if (pos == std::string::npos) return false;
        
        pos = json.find(":", pos);
        if (pos == std::string::npos) return false;
        
        pos = json.find_first_not_of(" \t\n\r", pos + 1);
        if (pos == std::string::npos) return false;
        
        if (json.substr(pos, 4) == "true") {
            value = true;
            return true;
        } else if (json.substr(pos, 5) == "false") {
            value = false;
            return true;
        }
        
        return false;
    }
    
    bool GetIntValue(const std::string& json, const std::string& key, int& value) {
        std::string search_key = "\"" + key + "\"";
        size_t pos = json.find(search_key);
        if (pos == std::string::npos) return false;
        
        pos = json.find(":", pos);
        if (pos == std::string::npos) return false;
        
        pos = json.find_first_not_of(" \t\n\r", pos + 1);
        if (pos == std::string::npos) return false;
        
        char* end_ptr = nullptr;
        value = static_cast<int>(strtol(json.c_str() + pos, &end_ptr, 10));
        return (end_ptr != json.c_str() + pos);
    }
    
    bool GetLongValue(const std::string& json, const std::string& key, long& value) {
        std::string search_key = "\"" + key + "\"";
        size_t pos = json.find(search_key);
        if (pos == std::string::npos) return false;
        
        pos = json.find(":", pos);
        if (pos == std::string::npos) return false;
        
        pos = json.find_first_not_of(" \t\n\r", pos + 1);
        if (pos == std::string::npos) return false;
        
        char* end_ptr = nullptr;
        value = strtol(json.c_str() + pos, &end_ptr, 10);
        return (end_ptr != json.c_str() + pos);
    }
    
    // Parse ISO 8601 date string (e.g., "2024-01-15T12:00:00+00:00" or "2024-01-15")
    bool ParseISODate(const std::string& date_str, int& year, int& month, int& day) {
        // Try to find date part (before 'T' or at start)
        size_t date_end = date_str.find('T');
        if (date_end == std::string::npos) {
            date_end = date_str.length();
        }
        
        std::string date_part = date_str.substr(0, date_end);
        
        // Format: YYYY-MM-DD
        if (date_part.length() >= 10 && date_part[4] == '-' && date_part[7] == '-') {
            year = std::stoi(date_part.substr(0, 4));
            month = std::stoi(date_part.substr(5, 2));
            day = std::stoi(date_part.substr(8, 2));
            return true;
        }
        
        return false;
    }
}

// Make HTTP request to Patreon API
static HttpResponse MakePatreonRequest(const std::string& url, const std::string& access_token, int timeout_seconds) {
    // Anti-debugging check
    Obfuscation::DeadCode1();
    if (Obfuscation::IsDebuggerPresent()) {
        Obfuscation::DeadCode2();
        HttpResponse empty_response;
        empty_response.success = false;
        empty_response.status_code = 0;
        return empty_response;
    }
    Obfuscation::DeadCode3();
    
#ifdef _WIN32
    return MakePatreonRequest_Windows(url, access_token, timeout_seconds);
#else
    return MakePatreonRequest_Linux(url, access_token, timeout_seconds);
#endif
}

// Validate input parameters
static bool ValidateInput(const char* access_token) {
    if (!access_token) {
        SetError("Access token is null");
        return false;
    }
    
    size_t token_len = strlen(access_token);
    if (token_len == 0) {
        SetError("Access token is empty");
        return false;
    }
    
    // Patreon OAuth2 tokens are typically 32+ characters
    // Very short tokens are likely invalid
    if (token_len < 16) {
        SetError("Invalid or expired access token");
        return false;
    }
    
    if (token_len > 2048) {
        SetError("Access token is too long");
        return false;
    }
    
    return true;
}

// Parse member status from Patreon API response
static bool ParseMemberStatus(const std::string& json_response, bool& is_active, std::string& tier_title, std::vector<std::string>& tier_ids) {
    is_active = false;
    tier_title.clear();
    tier_ids.clear();
    
    // Check if response is empty
    if (json_response.empty()) {
        return false;
    }
    
    // Check for "data" field in response (Patreon API structure)
    size_t data_pos = json_response.find("\"data\"");
    if (data_pos == std::string::npos) {
        // Check if it's an error response
        if (json_response.find("\"error\"") != std::string::npos) {
            return false; // Error response, not a valid member status
        }
        // Might be a different response format, try to parse anyway
    }
    
    // Look for membership status in "included" array (memberships are in included array)
    // Patreon API returns memberships in the "included" array when using include=memberships
    size_t included_pos = json_response.find("\"included\"");
    bool has_memberships = (included_pos != std::string::npos);
    
    // Check if included array exists and is not empty
    if (has_memberships) {
        // Check if included array is empty: "included":[]
        size_t included_array_start = json_response.find("\"included\":[", included_pos);
        if (included_array_start != std::string::npos) {
            size_t array_start = included_array_start + 11; // Length of "included":[
            size_t array_end = json_response.find("]", array_start);
            if (array_end != std::string::npos) {
                std::string array_content = json_response.substr(array_start, array_end - array_start);
                // Trim whitespace
                while (!array_content.empty() && (array_content[0] == ' ' || array_content[0] == '\n' || array_content[0] == '\t')) {
                    array_content = array_content.substr(1);
                }
                if (array_content.empty()) {
                    // Empty included array means no memberships - user is not a patron
                    is_active = false;
                    return true; // Valid response, just no memberships
                }
            }
        }
    }
    
    // If no included array, check if data has memberships directly
    if (!has_memberships) {
        // Check if data array is empty (user has no memberships)
        size_t data_array_start = json_response.find("\"data\":[");
        if (data_array_start != std::string::npos) {
            size_t data_array_end = json_response.find("]", data_array_start);
            if (data_array_end != std::string::npos) {
                std::string data_content = json_response.substr(data_array_start + 8, data_array_end - data_array_start - 8);
                // Trim whitespace
                while (!data_content.empty() && (data_content[0] == ' ' || data_content[0] == '\n' || data_content[0] == '\t')) {
                    data_content = data_content.substr(1);
                }
                if (data_content.empty() || data_content == "null") {
                    // Empty data array means no memberships - user is not a patron
                    is_active = false;
                    return true; // Valid response, just no memberships
                }
            }
        }
        // If no included array and no data array, user has no memberships
        is_active = false;
        return true;
    }
    
    // Check membership status - use multiple indicators for reliability
    // Only check this if we have memberships (included array is not empty)
    
    // PRIMARY CHECK: currently_entitled_amount_cents > 0
    // This is the most immediate indicator - shows they have active entitlement
    // Works even if last_charge_status is still "Pending" (can take up to 30 min after subscription)
    long entitled_amount = 0;
    bool has_entitlement = false;
    if (JsonHelper::GetLongValue(json_response, "currently_entitled_amount_cents", entitled_amount)) {
        has_entitlement = (entitled_amount > 0);
    }
    
    // SECONDARY CHECK: last_charge_status == "Paid"
    // This confirms payment was successful (but may be delayed for new subscriptions)
    std::string last_charge_status;
    bool has_paid_charge = false;
    if (JsonHelper::GetStringValue(json_response, "last_charge_status", last_charge_status)) {
        has_paid_charge = (last_charge_status == "Paid" || last_charge_status == "paid");
    }
    
    // Member is active if they have entitlement OR paid charge
    // This handles both:
    // - New subscriptions (entitlement set immediately, charge status may be pending)
    // - Existing subscriptions (charge status is paid)
    is_active = has_entitlement || has_paid_charge;
    
    // Extract tier title from included array
    // Tier title is in included array where type="tier", in attributes.title
    if (has_memberships) {
        // Find tier objects in included array
        size_t tier_type_pos = json_response.find("\"type\":\"tier\"", included_pos);
        
        // Search for all tier objects in included array
        while (tier_type_pos != std::string::npos && tier_type_pos < included_pos + 10000) {
            // Look for "attributes" section in tier object
            size_t attributes_pos = json_response.find("\"attributes\"", tier_type_pos);
            if (attributes_pos != std::string::npos && attributes_pos < tier_type_pos + 1000) {
                // Look for "title" in attributes
                size_t title_pos = json_response.find("\"title\"", attributes_pos);
                if (title_pos != std::string::npos && title_pos < attributes_pos + 500) {
                    // Extract title value
                    size_t title_value_start = json_response.find(":", title_pos);
                    if (title_value_start != std::string::npos) {
                        title_value_start++; // Skip colon
                        // Skip whitespace
                        while (title_value_start < json_response.length() && 
                               (json_response[title_value_start] == ' ' || 
                                json_response[title_value_start] == '\t' ||
                                json_response[title_value_start] == '\n')) {
                            title_value_start++;
                        }
                        
                        // Extract string value (should be quoted)
                        if (title_value_start < json_response.length() && 
                            json_response[title_value_start] == '"') {
                            title_value_start++; // Skip opening quote
                            size_t title_value_end = json_response.find("\"", title_value_start);
                            if (title_value_end != std::string::npos) {
                                tier_title = json_response.substr(title_value_start, title_value_end - title_value_start);
                                break; // Found first tier title, exit loop
                            }
                        }
                    }
                }
            }
            
            // Search for next tier object
            tier_type_pos = json_response.find("\"type\":\"tier\"", tier_type_pos + 1);
        }
        
        // Extract tier IDs from currently_entitled_tiers in relationships
        // Find the first member object in included array
        size_t member_type_pos = json_response.find("\"type\":\"member\"", included_pos);
        if (member_type_pos != std::string::npos) {
            // Look for "relationships" section after the type
            size_t relationships_pos = json_response.find("\"relationships\"", member_type_pos);
            if (relationships_pos != std::string::npos) {
                // Look for "currently_entitled_tiers" in relationships
                size_t entitled_tiers_pos = json_response.find("\"currently_entitled_tiers\"", relationships_pos);
                if (entitled_tiers_pos != std::string::npos && entitled_tiers_pos < relationships_pos + 1000) {
                    // Look for "data" array in currently_entitled_tiers
                    size_t entitled_data_pos = json_response.find("\"data\"", entitled_tiers_pos);
                    if (entitled_data_pos != std::string::npos && entitled_data_pos < entitled_tiers_pos + 200) {
                        // Look for array start: "data":[
                        size_t array_start = json_response.find("[", entitled_data_pos);
                        if (array_start != std::string::npos) {
                            size_t array_end = json_response.find("]", array_start);
                            if (array_end != std::string::npos) {
                                // Extract array content
                                std::string array_content = json_response.substr(array_start + 1, array_end - array_start - 1);
                                
                                // Parse tier IDs from array
                                size_t tier_obj_pos = 0;
                                while ((tier_obj_pos = array_content.find("{", tier_obj_pos)) != std::string::npos) {
                                    size_t tier_obj_end = array_content.find("}", tier_obj_pos);
                                    if (tier_obj_end != std::string::npos) {
                                        std::string tier_obj = array_content.substr(tier_obj_pos, tier_obj_end - tier_obj_pos + 1);
                                        
                                        // Extract tier ID from this object
                                        size_t id_pos = tier_obj.find("\"id\"");
                                        if (id_pos != std::string::npos) {
                                            size_t id_colon = tier_obj.find(":", id_pos);
                                            if (id_colon != std::string::npos) {
                                                id_colon++;
                                                // Skip whitespace
                                                while (id_colon < tier_obj.length() && 
                                                       (tier_obj[id_colon] == ' ' || tier_obj[id_colon] == '\t' || tier_obj[id_colon] == '\n')) {
                                                    id_colon++;
                                                }
                                                
                                                std::string tier_id_str;
                                                if (id_colon < tier_obj.length() && tier_obj[id_colon] == '"') {
                                                    id_colon++;
                                                    size_t id_end = tier_obj.find("\"", id_colon);
                                                    if (id_end != std::string::npos) {
                                                        tier_id_str = tier_obj.substr(id_colon, id_end - id_colon);
                                                    }
                                                } else {
                                                    // Number ID
                                                    size_t id_end = id_colon;
                                                    while (id_end < tier_obj.length() && 
                                                           tier_obj[id_end] != ',' && tier_obj[id_end] != '}' &&
                                                           tier_obj[id_end] != ' ' && tier_obj[id_end] != '\n') {
                                                        id_end++;
                                                    }
                                                    if (id_end > id_colon) {
                                                        tier_id_str = tier_obj.substr(id_colon, id_end - id_colon);
                                                    }
                                                }
                                                
                                                if (!tier_id_str.empty()) {
                                                    tier_ids.push_back(tier_id_str);
                                                }
                                            }
                                        }
                                        tier_obj_pos = tier_obj_end + 1;
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Note: We use currently_entitled_amount_cents OR last_charge_status because:
    // - currently_entitled_amount_cents > 0 indicates active entitlement (immediate)
    // - last_charge_status == "Paid" confirms payment (may be delayed up to 30 min for new subscriptions)
    // - We intentionally DO NOT check patron_status because it can be "active_patron" for former patrons
    
    return true;
}

// Helper function to parse member details from JSON
static bool ParseMemberDetails(const std::string& json_response, PATREON_MemberDetails* details) {
    if (!details) return false;
    
    // Initialize structure
    details->is_free_tier = 0;
    details->is_free_trial = 0;
    details->tier_id = 0;
    details->currently_entitled_amount_cents = 0;
    details->is_email_verified = 0;
    details->is_creator = 0;
    details->can_see_nsfw = 0;
    memset(details->subscription_type, 0, sizeof(details->subscription_type));
    memset(details->tier_description, 0, sizeof(details->tier_description));
    memset(details->created, 0, sizeof(details->created));
    memset(details->first_name, 0, sizeof(details->first_name));
    memset(details->last_name, 0, sizeof(details->last_name));
    
    // Get currently_entitled_amount_cents
    long entitled_amount = 0;
    if (JsonHelper::GetLongValue(json_response, "currently_entitled_amount_cents", entitled_amount)) {
        details->currently_entitled_amount_cents = entitled_amount;
    }
    
    // Check if free trial
    bool is_free_trial = false;
    if (JsonHelper::GetBoolValue(json_response, "is_free_trial", is_free_trial)) {
        details->is_free_trial = is_free_trial ? 1 : 0;
    }
    
    // Extract tier IDs from currently_entitled_tiers (active tiers only)
    // Then match them with titles from included array
    size_t included_pos = json_response.find("\"included\"");
    bool has_memberships = (included_pos != std::string::npos);
    
    std::vector<std::string> active_tier_ids;  // Store all active tier IDs
    std::map<std::string, std::string> tier_id_to_title;  // Map tier ID to title
    bool found_any_tier = false;
    
    if (has_memberships) {
        // First, extract all tier IDs from currently_entitled_tiers in relationships
        size_t member_type_pos = json_response.find("\"type\":\"member\"", included_pos);
        if (member_type_pos != std::string::npos) {
            size_t relationships_pos = json_response.find("\"relationships\"", member_type_pos);
            if (relationships_pos != std::string::npos) {
                // Look for currently_entitled_tiers in relationships
                size_t entitled_tiers_pos = json_response.find("\"currently_entitled_tiers\"", relationships_pos);
                if (entitled_tiers_pos != std::string::npos && entitled_tiers_pos < relationships_pos + 1000) {
                    // Look for "data" array in currently_entitled_tiers
                    size_t entitled_data_pos = json_response.find("\"data\"", entitled_tiers_pos);
                    if (entitled_data_pos != std::string::npos && entitled_data_pos < entitled_tiers_pos + 200) {
                        // Look for array start: "data":[
                        size_t array_start = json_response.find("[", entitled_data_pos);
                        if (array_start != std::string::npos) {
                            size_t array_end = json_response.find("]", array_start);
                            if (array_end != std::string::npos) {
                                // Extract array content
                                std::string array_content = json_response.substr(array_start + 1, array_end - array_start - 1);
                                
                                // Parse tier IDs from array
                                size_t tier_obj_pos = 0;
                                while ((tier_obj_pos = array_content.find("{", tier_obj_pos)) != std::string::npos) {
                                    size_t tier_obj_end = array_content.find("}", tier_obj_pos);
                                    if (tier_obj_end != std::string::npos) {
                                        std::string tier_obj = array_content.substr(tier_obj_pos, tier_obj_end - tier_obj_pos + 1);
                                        
                                        // Extract tier ID from this object
                                        size_t id_pos = tier_obj.find("\"id\"");
                                        if (id_pos != std::string::npos) {
                                            size_t id_colon = tier_obj.find(":", id_pos);
                                            if (id_colon != std::string::npos) {
                                                id_colon++;
                                                // Skip whitespace
                                                while (id_colon < tier_obj.length() && 
                                                       (tier_obj[id_colon] == ' ' || tier_obj[id_colon] == '\t' || tier_obj[id_colon] == '\n')) {
                                                    id_colon++;
                                                }
                                                
                                                std::string tier_id_str;
                                                if (id_colon < tier_obj.length() && tier_obj[id_colon] == '"') {
                                                    id_colon++;
                                                    size_t id_end = tier_obj.find("\"", id_colon);
                                                    if (id_end != std::string::npos) {
                                                        tier_id_str = tier_obj.substr(id_colon, id_end - id_colon);
                                                    }
                                                } else {
                                                    // Number ID
                                                    size_t id_end = id_colon;
                                                    while (id_end < tier_obj.length() && 
                                                           tier_obj[id_end] != ',' && tier_obj[id_end] != '}' &&
                                                           tier_obj[id_end] != ' ' && tier_obj[id_end] != '\n') {
                                                        id_end++;
                                                    }
                                                    if (id_end > id_colon) {
                                                        tier_id_str = tier_obj.substr(id_colon, id_end - id_colon);
                                                    }
                                                }
                                                
                                                if (!tier_id_str.empty()) {
                                                    active_tier_ids.push_back(tier_id_str);
                                                    found_any_tier = true;
                                                }
                                            }
                                        }
                                        tier_obj_pos = tier_obj_end + 1;
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Now, build a map of tier ID to title from included array
        size_t tier_type_pos = json_response.find("\"type\":\"tier\"", included_pos);
        
        // Search for all tier objects in included array
        while (tier_type_pos != std::string::npos && tier_type_pos < included_pos + 10000) {
            // Extract tier ID from this tier object (to build map)
            size_t tier_obj_start = tier_type_pos;
            while (tier_obj_start > included_pos && tier_obj_start > 0 && json_response[tier_obj_start] != '{') {
                tier_obj_start--;
            }
            
            size_t attributes_pos_for_id = json_response.find("\"attributes\"", tier_type_pos);
            size_t search_end = tier_type_pos + 200;
            if (attributes_pos_for_id != std::string::npos && attributes_pos_for_id < search_end) {
                search_end = attributes_pos_for_id;
            }
            
            size_t tier_id_pos = json_response.find("\"id\"", tier_obj_start);
            while (tier_id_pos != std::string::npos && tier_id_pos < tier_type_pos + 1000) {
                if (attributes_pos_for_id == std::string::npos || tier_id_pos < attributes_pos_for_id) {
                    if (tier_id_pos < search_end) {
                        break;
                    }
                }
                tier_id_pos = json_response.find("\"id\"", tier_id_pos + 1);
            }
            
            std::string current_tier_id_str;
            if (tier_id_pos != std::string::npos && tier_id_pos < search_end) {
                size_t id_value_start = json_response.find(":", tier_id_pos);
                if (id_value_start != std::string::npos && id_value_start < search_end) {
                    id_value_start++;
                    while (id_value_start < json_response.length() && 
                           (json_response[id_value_start] == ' ' || 
                            json_response[id_value_start] == '\t' ||
                            json_response[id_value_start] == '\n')) {
                        id_value_start++;
                    }
                    
                    if (id_value_start < json_response.length() && json_response[id_value_start] == '"') {
                        id_value_start++;
                        size_t id_value_end = json_response.find("\"", id_value_start);
                        if (id_value_end != std::string::npos) {
                            current_tier_id_str = json_response.substr(id_value_start, id_value_end - id_value_start);
                        }
                    } else {
                        size_t id_value_end = id_value_start;
                        while (id_value_end < json_response.length() && 
                               json_response[id_value_end] != ',' && 
                               json_response[id_value_end] != '}' &&
                               json_response[id_value_end] != ' ' &&
                               json_response[id_value_end] != '\n') {
                            id_value_end++;
                        }
                        if (id_value_end > id_value_start) {
                            current_tier_id_str = json_response.substr(id_value_start, id_value_end - id_value_start);
                        }
                    }
                }
            }
            
            // Look for "attributes" section in tier object (for title)
            size_t attributes_pos = json_response.find("\"attributes\"", tier_type_pos);
            if (attributes_pos != std::string::npos && attributes_pos < tier_type_pos + 1000) {
                // Look for "title" in attributes
                size_t title_pos = json_response.find("\"title\"", attributes_pos);
                if (title_pos != std::string::npos && title_pos < attributes_pos + 500) {
                    // Extract title value
                    size_t title_value_start = json_response.find(":", title_pos);
                    if (title_value_start != std::string::npos) {
                        title_value_start++; // Skip colon
                        // Skip whitespace
                        while (title_value_start < json_response.length() && 
                               (json_response[title_value_start] == ' ' || 
                                json_response[title_value_start] == '\t' ||
                                json_response[title_value_start] == '\n')) {
                            title_value_start++;
                        }
                        
                        // Extract string value (should be quoted)
                        if (title_value_start < json_response.length() && 
                            json_response[title_value_start] == '"') {
                            title_value_start++; // Skip opening quote
                            size_t title_value_end = json_response.find("\"", title_value_start);
                            if (title_value_end != std::string::npos) {
                                std::string extracted_title = json_response.substr(title_value_start, title_value_end - title_value_start);
                                
                                // Store tier ID to title mapping
                                if (!current_tier_id_str.empty()) {
                                    tier_id_to_title[current_tier_id_str] = extracted_title;
                                }
                            }
                        }
                    }
                }
            }
            
            // Search for next tier object
            tier_type_pos = json_response.find("\"type\":\"tier\"", tier_type_pos + 1);
        }
        
        // Build list of active tier titles and IDs (matching currently_entitled_tiers IDs)
        std::string active_tiers_list;  // Titles separated by comma
        std::string active_tier_ids_list;  // IDs separated by comma
        int first_tier_id = 0;
        
        for (const auto& tier_id : active_tier_ids) {
            auto it = tier_id_to_title.find(tier_id);
            std::string tier_title = (it != tier_id_to_title.end()) ? it->second : "";
            
            // Build titles list (only active tiers from currently_entitled_tiers)
            if (!active_tiers_list.empty()) {
                active_tiers_list += ", ";
            }
            if (!tier_title.empty()) {
                active_tiers_list += tier_title;
            } else {
                active_tiers_list += "[ID: " + tier_id + "]";
            }
            
            // Build IDs list
            if (!active_tier_ids_list.empty()) {
                active_tier_ids_list += ", ";
            }
            active_tier_ids_list += tier_id;
            
            // Store first tier ID as tier_id (for backward compatibility)
            if (first_tier_id == 0 && !tier_id.empty()) {
                char* end_ptr = nullptr;
                long tier_id_long = strtol(tier_id.c_str(), &end_ptr, 10);
                if (end_ptr != tier_id.c_str() && *end_ptr == '\0') {
                    first_tier_id = static_cast<int>(tier_id_long);
                }
            }
        }
        
        // Store tier information
        if (found_any_tier && first_tier_id > 0) {
            details->tier_id = first_tier_id;
        } else if (!found_any_tier) {
            details->tier_id = -1;
        }
        
        // Store active tier titles and IDs in tier_description
        // Format: "Title1, Title2 |IDS| ID1, ID2"
        // This allows CLI to extract both titles and IDs
        std::string combined_output = active_tiers_list;
        if (!active_tier_ids_list.empty() && !active_tiers_list.empty()) {
            combined_output += " |IDS| " + active_tier_ids_list;
        } else if (!active_tier_ids_list.empty()) {
            combined_output = active_tier_ids_list;  // Only IDs if no titles
        }
        
        if (!combined_output.empty()) {
            size_t copy_len = combined_output.length();
            if (copy_len > sizeof(details->tier_description) - 1) {
                copy_len = sizeof(details->tier_description) - 1;
            }
            strncpy(details->tier_description, combined_output.c_str(), copy_len);
            details->tier_description[copy_len] = '\0';
        }
    } else {
        // No memberships/included array - set tier_id to -1
        details->tier_id = -1;
    }
    
    // Determine subscription type
    if (details->currently_entitled_amount_cents == 0) {
        details->is_free_tier = 1;
        strncpy(details->subscription_type, "Free", sizeof(details->subscription_type) - 1);
    } else if (details->is_free_trial) {
        details->is_free_tier = 0;
        strncpy(details->subscription_type, "Free Trial", sizeof(details->subscription_type) - 1);
    } else {
        details->is_free_tier = 0;
        strncpy(details->subscription_type, "Paid", sizeof(details->subscription_type) - 1);
    }
    
    // Extract user attributes from data.attributes (user object in root data)
    // User attributes are in the root data object, not in included array
    size_t data_pos = json_response.find("\"data\"");
    if (data_pos != std::string::npos) {
        // Find user type
        size_t user_type_pos = json_response.find("\"type\":\"user\"", data_pos);
        if (user_type_pos != std::string::npos) {
            // Look for "attributes" section in user object
            size_t user_attributes_pos = json_response.find("\"attributes\"", user_type_pos);
            if (user_attributes_pos != std::string::npos && user_attributes_pos < user_type_pos + 500) {
                // Extract the attributes section (from { to })
                size_t attr_start = json_response.find("{", user_attributes_pos);
                if (attr_start != std::string::npos) {
                    // Find matching closing brace
                    int brace_count = 0;
                    size_t attr_end = attr_start;
                    for (size_t i = attr_start; i < json_response.length() && i < attr_start + 2000; i++) {
                        if (json_response[i] == '{') brace_count++;
                        else if (json_response[i] == '}') {
                            brace_count--;
                            if (brace_count == 0) {
                                attr_end = i + 1;
                                break;
                            }
                        }
                    }
                    
                    if (attr_end > attr_start) {
                        std::string user_attributes = json_response.substr(attr_start, attr_end - attr_start);
                        
                        // Parse user fields from attributes
                        std::string created_str;
                        if (JsonHelper::GetStringValue(user_attributes, "created", created_str)) {
                            size_t copy_len = created_str.length();
                            if (copy_len > sizeof(details->created) - 1) {
                                copy_len = sizeof(details->created) - 1;
                            }
                            strncpy(details->created, created_str.c_str(), copy_len);
                            details->created[copy_len] = '\0';
                        }
                        
                        std::string first_name_str;
                        if (JsonHelper::GetStringValue(user_attributes, "first_name", first_name_str)) {
                            size_t copy_len = first_name_str.length();
                            if (copy_len > sizeof(details->first_name) - 1) {
                                copy_len = sizeof(details->first_name) - 1;
                            }
                            strncpy(details->first_name, first_name_str.c_str(), copy_len);
                            details->first_name[copy_len] = '\0';
                        }
                        
                        std::string last_name_str;
                        if (JsonHelper::GetStringValue(user_attributes, "last_name", last_name_str)) {
                            size_t copy_len = last_name_str.length();
                            if (copy_len > sizeof(details->last_name) - 1) {
                                copy_len = sizeof(details->last_name) - 1;
                            }
                            strncpy(details->last_name, last_name_str.c_str(), copy_len);
                            details->last_name[copy_len] = '\0';
                        }
                        
                        bool is_email_verified_val = false;
                        if (JsonHelper::GetBoolValue(user_attributes, "is_email_verified", is_email_verified_val)) {
                            details->is_email_verified = is_email_verified_val ? 1 : 0;
                        }
                        
                        bool is_creator_val = false;
                        if (JsonHelper::GetBoolValue(user_attributes, "is_creator", is_creator_val)) {
                            details->is_creator = is_creator_val ? 1 : 0;
                        }
                        
                        bool can_see_nsfw_val = false;
                        if (JsonHelper::GetBoolValue(user_attributes, "can_see_nsfw", can_see_nsfw_val)) {
                            details->can_see_nsfw = can_see_nsfw_val ? 1 : 0;
                        }
                    }
                }
            }
        }
    }
    
    return true;
}

// Implementation of exported functions
extern "C" {

int PATREON_VerifyMember(const char* access_token, const char* campaign_id, const char* tier_title, const char* tier_id, int timeout_seconds) {
    try {
        SecurityUtils::LogMessage("PATREON_VerifyMember called");
        
        // Anti-debugging and integrity checks
        Obfuscation::DeadCode1();
        if (Obfuscation::IsDebuggerPresent()) {
            Obfuscation::DeadCode2();
            SecurityUtils::LogMessage("Debugger detected - verification blocked");
            SetError("Invalid or expired access token");
            return PATREON_ERROR_INVALID_TOKEN; // Fail silently if debugger detected - return token error for security
        }
        if (!Obfuscation::VerifyIntegrity()) {
            Obfuscation::DeadCode3();
            SecurityUtils::LogMessage("Integrity check failed - verification blocked");
            SetError("Invalid or expired access token");
            return PATREON_ERROR_INVALID_TOKEN; // Fail if tampering detected - return token error for security
        }
        
        // Anti-patching check
        if (PATREON_IsClientPatched() == 1) {
            Obfuscation::DeadCode1();
            SecurityUtils::LogMessage("Client patching detected - verification blocked");
            SetError("Invalid or expired access token");
            return PATREON_ERROR_INVALID_TOKEN; // Fail if patching detected - return token error for security
        }
        
        // Verify client integrity
        if (PATREON_VerifyClientIntegrity() == 0) {
            Obfuscation::DeadCode2();
            SecurityUtils::LogMessage("Client integrity check failed - verification blocked");
            SetError("Invalid or expired access token");
            return PATREON_ERROR_INVALID_TOKEN; // Fail if integrity check failed - return token error for security
        }
        
        Obfuscation::DeadCode2();
        
        // Input validation with specific token length check
        size_t token_len = access_token ? strlen(access_token) : 0;
        if (!access_token || token_len == 0) {
            SecurityUtils::LogMessage("Access token is null or empty");
            SetError("Access token is null or empty");
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        // Patreon OAuth2 tokens are typically 32+ characters
        // Very short tokens (< 16 chars) are likely invalid and should return INVALID_TOKEN
        if (token_len < 16) {
            SecurityUtils::LogMessage("Token too short: " + std::to_string(token_len) + " characters");
            SetError("Invalid or expired access token");
            return PATREON_ERROR_INVALID_TOKEN;
        }
        
        if (token_len > 2048) {
            SecurityUtils::LogMessage("Token too long: " + std::to_string(token_len) + " characters");
            SetError("Access token is too long");
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        // Get HWID for enhanced rate limiting
        char hwid_buffer[256] = {0};
        size_t hwid_len = PATREON_GetHardwareID(hwid_buffer, sizeof(hwid_buffer));
        std::string hwid_str = (hwid_len > 0) ? std::string(hwid_buffer) : "";
        
        // Enhanced rate limiting check (per-token and per-HWID)
        std::string token_str(access_token);
        if (!SecurityUtils::CheckEnhancedRateLimit(token_str, hwid_str)) {
            SetError("Rate limit exceeded - too many requests");
            SecurityUtils::LogMessage("Rate limit exceeded for token: " + token_str.substr(0, 10) + "...");
            return PATREON_ERROR_NETWORK;
        }
        
        // Check if token needs refresh
        if (PATREON_TokenNeedsRefresh(access_token) == 1) {
            SecurityUtils::LogMessage("Token needs refresh - consider refreshing before expiration");
        }
        
        SecurityUtils::LogMessage("Verifying Patreon membership for token: " + token_str.substr(0, 10) + "...");
        
        // Build API URL (obfuscated)
        // Include tiers to get title field
        Obfuscation::DeadCode1();
        std::string base_url = Obfuscation::GetBaseURL();
        std::string params = "include=memberships.currently_entitled_tiers&fields[member]=last_charge_status,patron_status,currently_entitled_amount_cents&fields[tier]=title";
        std::string url = base_url + "?" + params;
        Obfuscation::DeadCode3();
        
        SecurityUtils::LogMessage("Making request to: " + base_url + " (URL truncated for security)");
        SecurityUtils::LogMessage("Request timeout: " + std::to_string(timeout_seconds > 0 ? timeout_seconds : 30) + " seconds");
        
        // Make request
        HttpResponse response = MakePatreonRequest(url, access_token, timeout_seconds > 0 ? timeout_seconds : 30);
        
        SecurityUtils::LogMessage("Request completed - success: " + std::string(response.success ? "true" : "false") + 
                                 ", status_code: " + std::to_string(response.status_code) +
                                 ", data_length: " + std::to_string(response.data.length()));
        
        if (!response.success) {
            if (response.status_code == 0) {
                SecurityUtils::LogMessage("Network error - status_code is 0, request may have failed to connect");
                char error_buffer[512] = {0};
                PATREON_GetLastError(error_buffer, sizeof(error_buffer));
                if (strlen(error_buffer) > 0) {
                    SecurityUtils::LogMessage("Last error: " + std::string(error_buffer));
                }
                SetError("Network connection error - unable to reach Patreon API");
                return PATREON_ERROR_NETWORK;
            }
            if (response.status_code == 401 || response.status_code == 403) {
                // Log response details for debugging
                std::string error_details = "HTTP " + std::to_string(response.status_code);
                if (!response.data.empty()) {
                    // Truncate long responses for logging
                    std::string log_data = response.data.length() > 500 
                        ? response.data.substr(0, 500) + "..." 
                        : response.data;
                    SecurityUtils::LogMessage("API Error Response: " + log_data);
                    error_details += " - " + log_data;
                }
                SetError("Invalid or expired access token (HTTP " + std::to_string(response.status_code) + ")");
                SecurityUtils::LogMessage("Token verification failed: " + error_details);
                return PATREON_ERROR_INVALID_TOKEN;
            }
            std::string error_msg = "HTTP error: " + std::to_string(response.status_code);
            if (!response.data.empty() && response.data.length() < 200) {
                error_msg += " - " + response.data;
            }
            SetError(error_msg);
            SecurityUtils::LogMessage("API request failed: " + error_msg);
            return PATREON_ERROR_INVALID_RESPONSE;
        }
        
        // Log successful response for debugging (truncated)
        if (!response.data.empty()) {
            std::string log_data = response.data.length() > 500 
                ? response.data.substr(0, 500) + "..." 
                : response.data;
            SecurityUtils::LogMessage("API Response received: " + log_data);
        }
        
        // Parse response
        bool is_active = false;
        std::string member_tier_title;
        std::vector<std::string> member_tier_ids;
        if (!ParseMemberStatus(response.data, is_active, member_tier_title, member_tier_ids)) {
            // Check if response is valid JSON but just doesn't have memberships
            if (response.data.find("\"data\"") != std::string::npos) {
                // Response has data field but parsing failed - might be empty memberships
                SecurityUtils::LogMessage("API response has data but no memberships found");
                SetError("User is not subscribed to any creator");
                return PATREON_ERROR_NOT_MEMBER;
            }
            // Log full response for debugging if parsing fails
            std::string log_data = response.data.length() > 1000 
                ? response.data.substr(0, 1000) + "..." 
                : response.data;
            SecurityUtils::LogMessage("Failed to parse Patreon API response: " + log_data);
            SetError("Failed to parse API response - invalid JSON format");
            return PATREON_ERROR_INVALID_RESPONSE;
        }
        
        // Check specific tier if requested (tier_id takes precedence over tier_title)
        if (tier_id && strlen(tier_id) > 0) {
            // Check if member has this tier ID
            std::string requested_id(tier_id);
            bool found_tier_id = false;
            for (const auto& member_id : member_tier_ids) {
                if (member_id == requested_id) {
                    found_tier_id = true;
                    break;
                }
            }
            
            if (!found_tier_id) {
                std::string member_ids_str = member_tier_ids.empty() ? "none" : member_tier_ids[0];
                for (size_t i = 1; i < member_tier_ids.size(); i++) {
                    member_ids_str += ", " + member_tier_ids[i];
                }
                SecurityUtils::LogMessage("Tier ID mismatch - requested: " + std::string(tier_id) + 
                          ", user has: " + member_ids_str);
                return PATREON_ERROR_NOT_MEMBER;
            }
        } else if (tier_title && strlen(tier_title) > 0) {
            // Case-insensitive comparison
            std::string requested_title(tier_title);
            std::string member_title(member_tier_title);
            
            // Convert to lowercase for comparison
            std::transform(requested_title.begin(), requested_title.end(), requested_title.begin(), ::tolower);
            std::transform(member_title.begin(), member_title.end(), member_title.begin(), ::tolower);
            
            // Trim whitespace
            requested_title.erase(0, requested_title.find_first_not_of(" \t\n\r"));
            requested_title.erase(requested_title.find_last_not_of(" \t\n\r") + 1);
            member_title.erase(0, member_title.find_first_not_of(" \t\n\r"));
            member_title.erase(member_title.find_last_not_of(" \t\n\r") + 1);
            
            if (requested_title != member_title) {
                SecurityUtils::LogMessage("Tier mismatch - requested: " + std::string(tier_title) + 
                          ", user has: " + member_tier_title);
                return PATREON_ERROR_NOT_MEMBER;
            }
        }
        
        int result = is_active ? PATREON_SUCCESS : PATREON_ERROR_NOT_MEMBER;
        SecurityUtils::LogMessage("Verification result: " + std::string(result == PATREON_SUCCESS ? "SUCCESS" : "NOT_MEMBER") +
                  " (Tier: " + (member_tier_title.empty() ? "none" : member_tier_title) + ")");
        
        return result;
    }
    catch (const std::bad_alloc&) {
        SetError("Memory allocation failed");
        return PATREON_ERROR_MEMORY;
    }
    catch (...) {
        // For any exceptions during token verification, treat as invalid token
        // This handles cases where invalid tokens cause parsing/request errors
        // This is safer than exposing internal errors
        SetError("Invalid or expired access token");
        return PATREON_ERROR_INVALID_TOKEN;
    }
}

int PATREON_GetMemberInfo(const char* access_token, char* member_info, size_t buffer_size, int timeout_seconds) {
    try {
        // Anti-debugging and integrity checks
        Obfuscation::DeadCode2();
        if (Obfuscation::IsDebuggerPresent()) {
            Obfuscation::DeadCode1();
            return PATREON_ERROR_UNKNOWN;
        }
        if (!Obfuscation::VerifyIntegrity()) {
            Obfuscation::DeadCode3();
            return PATREON_ERROR_UNKNOWN;
        }
        
        // Anti-patching check
        if (PATREON_IsClientPatched() == 1) {
            Obfuscation::DeadCode1();
            SecurityUtils::LogMessage("Client patching detected - get info blocked");
            return PATREON_ERROR_UNKNOWN;
        }
        
        // Verify client integrity
        if (PATREON_VerifyClientIntegrity() == 0) {
            Obfuscation::DeadCode2();
            SecurityUtils::LogMessage("Client integrity check failed - get info blocked");
            return PATREON_ERROR_UNKNOWN;
        }
        
        Obfuscation::DeadCode1();
        
        // Input validation
        if (!ValidateInput(access_token)) {
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        if (!member_info || buffer_size == 0) {
            SetError("Invalid output buffer");
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        // Get HWID for enhanced rate limiting
        char hwid_buffer[256] = {0};
        size_t hwid_len = PATREON_GetHardwareID(hwid_buffer, sizeof(hwid_buffer));
        std::string hwid_str = (hwid_len > 0) ? std::string(hwid_buffer) : "";
        
        // Enhanced rate limiting check (per-token and per-HWID)
        std::string token_str(access_token);
        if (!SecurityUtils::CheckEnhancedRateLimit(token_str, hwid_str)) {
            SetError("Rate limit exceeded - too many requests");
            SecurityUtils::LogMessage("Rate limit exceeded for token: " + token_str.substr(0, 10) + "...");
            return PATREON_ERROR_NETWORK;
        }
        
        // Check if token needs refresh
        if (PATREON_TokenNeedsRefresh(access_token) == 1) {
            SecurityUtils::LogMessage("Token needs refresh - consider refreshing before expiration");
        }
        
        SecurityUtils::LogMessage("Getting member info for token: " + token_str.substr(0, 10) + "...");
        
        // Build API URL (obfuscated)
        Obfuscation::DeadCode3();
        std::string base_url = Obfuscation::GetBaseURL();
        std::string params = "include=memberships&fields[member]=last_charge_status,patron_status,currently_entitled_amount_cents,lifetime_support_cents";
        std::string url = base_url + "?" + params;
        Obfuscation::DeadCode2();
        
        // Make request
        HttpResponse response = MakePatreonRequest(url, access_token, timeout_seconds > 0 ? timeout_seconds : 30);
        
        if (!response.success) {
            if (response.status_code == 0) {
                SetError("Network connection error - unable to reach Patreon API");
                return PATREON_ERROR_NETWORK;
            }
            if (response.status_code == 401 || response.status_code == 403) {
                SetError("Invalid or expired access token");
                return PATREON_ERROR_INVALID_TOKEN;
            }
            SetError("HTTP error: " + std::to_string(response.status_code));
            return PATREON_ERROR_INVALID_RESPONSE;
        }
        
        // Copy response to buffer (safe copy)
        SafeStringCopy(member_info, buffer_size, response.data);
        
        return PATREON_SUCCESS;
    }
    catch (const std::bad_alloc&) {
        SetError("Memory allocation failed");
        return PATREON_ERROR_MEMORY;
    }
    catch (...) {
        SetError("Unknown error occurred");
        return PATREON_ERROR_UNKNOWN;
    }
}

int PATREON_CheckTierAccess(const char* access_token, const char* tier_title, int timeout_seconds) {
    try {
        // Anti-debugging check
        Obfuscation::DeadCode3();
        if (Obfuscation::IsDebuggerPresent()) {
            Obfuscation::DeadCode1();
            return PATREON_ERROR_UNKNOWN;
        }
        
        // Anti-patching check
        if (PATREON_IsClientPatched() == 1) {
            Obfuscation::DeadCode2();
            SecurityUtils::LogMessage("Client patching detected - tier check blocked");
            return PATREON_ERROR_UNKNOWN;
        }
        
        Obfuscation::DeadCode2();
        
        // Input validation
        if (!ValidateInput(access_token)) {
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        if (!tier_title || strlen(tier_title) == 0) {
            SetError("Invalid tier title");
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        // Use VerifyMember with tier check
        int result = PATREON_VerifyMember(access_token, nullptr, tier_title, nullptr, timeout_seconds);
        
        if (result == PATREON_SUCCESS) {
            return PATREON_STATUS_ACTIVE;
        } else if (result == PATREON_ERROR_NOT_MEMBER) {
            return PATREON_STATUS_INACTIVE;
        }
        
        return result;
    }
    catch (...) {
        SetError("Unknown error occurred");
        return PATREON_ERROR_UNKNOWN;
    }
}

size_t PATREON_GetLastError(char* error_buffer, size_t buffer_size) {
    if (!error_buffer || buffer_size == 0) {
        return 0;
    }
    
    std::lock_guard<std::mutex> lock(error_mutex);
    
    // Calculate copy size
    size_t copy_size = (last_error.length() < buffer_size - 1) ? last_error.length() : buffer_size - 1;
    
    // Safe copy with guaranteed null terminator
    SafeStringCopy(error_buffer, buffer_size, last_error);
    
    return copy_size;
}

int PATREON_GetSubscriptionHistory(const char* access_token, PATREON_SubscriptionHistory* history, int timeout_seconds) {
    try {
        // Anti-debugging and integrity checks
        Obfuscation::DeadCode1();
        if (Obfuscation::IsDebuggerPresent()) {
            Obfuscation::DeadCode2();
            return PATREON_ERROR_UNKNOWN;
        }
        if (!Obfuscation::VerifyIntegrity()) {
            Obfuscation::DeadCode3();
            return PATREON_ERROR_UNKNOWN;
        }
        
        // Anti-patching check
        if (PATREON_IsClientPatched() == 1) {
            Obfuscation::DeadCode1();
            SecurityUtils::LogMessage("Client patching detected - history request blocked");
            return PATREON_ERROR_UNKNOWN;
        }
        
        // Verify client integrity
        if (PATREON_VerifyClientIntegrity() == 0) {
            Obfuscation::DeadCode2();
            SecurityUtils::LogMessage("Client integrity check failed - history request blocked");
            return PATREON_ERROR_UNKNOWN;
        }
        
        Obfuscation::DeadCode2();
        
        // Input validation
        if (!ValidateInput(access_token)) {
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        if (!history) {
            SetError("History output structure is null");
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        // Initialize history structure
        memset(history, 0, sizeof(PATREON_SubscriptionHistory));
        
        // Get HWID for enhanced rate limiting
        char hwid_buffer[256] = {0};
        size_t hwid_len = PATREON_GetHardwareID(hwid_buffer, sizeof(hwid_buffer));
        std::string hwid_str = (hwid_len > 0) ? std::string(hwid_buffer) : "";
        
        // Enhanced rate limiting check
        std::string token_str(access_token);
        if (!SecurityUtils::CheckEnhancedRateLimit(token_str, hwid_str)) {
            SetError("Rate limit exceeded - too many requests");
            SecurityUtils::LogMessage("Rate limit exceeded for token: " + token_str.substr(0, 10) + "...");
            return PATREON_ERROR_NETWORK;
        }
        
        SecurityUtils::LogMessage("Getting subscription history for token: " + token_str.substr(0, 10) + "...");
        
        // Build API URL to get member information with history fields
        // Use correct Patreon API v2 fields: pledge_relationship_start, campaign_lifetime_support_cents, patron_status
        Obfuscation::DeadCode3();
        std::string base_url = Obfuscation::GetBaseURL();
        std::string params = "include=memberships&fields[member]=pledge_relationship_start,campaign_lifetime_support_cents,patron_status";
        std::string url = base_url + "?" + params;
        Obfuscation::DeadCode1();
        
        // Make request
        HttpResponse response = MakePatreonRequest(url, access_token, timeout_seconds > 0 ? timeout_seconds : 30);
        
        if (!response.success) {
            if (response.status_code == 0) {
                SetError("Network connection error - unable to reach Patreon API");
                return PATREON_ERROR_NETWORK;
            }
            if (response.status_code == 401 || response.status_code == 403) {
                SetError("Invalid or expired access token");
                return PATREON_ERROR_INVALID_TOKEN;
            }
            SetError("HTTP error: " + std::to_string(response.status_code));
            return PATREON_ERROR_INVALID_RESPONSE;
        }
        
        // Parse response to extract history information
        // Member fields are in the included memberships array, not at root level
        std::string pledge_relationship_start;
        long lifetime_support = 0;
        std::string patron_status_str;
        bool is_active = false;
        
        // Extract member attributes from included array
        size_t included_pos = response.data.find("\"included\"");
        std::string member_attributes;
        if (included_pos != std::string::npos) {
            // Find the first member object in included array
            size_t member_type_pos = response.data.find("\"type\":\"member\"", included_pos);
            
            if (member_type_pos != std::string::npos) {
                // Look for "attributes" section after the type
                size_t attributes_pos = response.data.find("\"attributes\"", member_type_pos);
                if (attributes_pos != std::string::npos) {
                    // Extract the attributes section (from { to })
                    size_t attr_start = response.data.find("{", attributes_pos);
                    if (attr_start != std::string::npos) {
                        // Find matching closing brace
                        int brace_count = 0;
                        size_t attr_end = attr_start;
                        for (size_t i = attr_start; i < response.data.length() && i < attr_start + 2000; i++) {
                            if (response.data[i] == '{') brace_count++;
                            else if (response.data[i] == '}') {
                                brace_count--;
                                if (brace_count == 0) {
                                    attr_end = i + 1;
                                    break;
                                }
                            }
                        }
                        
                        if (attr_end > attr_start) {
                            member_attributes = response.data.substr(attr_start, attr_end - attr_start);
                        }
                    }
                }
            }
        }
        
        // Parse fields from member attributes (included array) or fallback to root level
        if (!member_attributes.empty()) {
            // Get pledge_relationship_start from member attributes (Member Since)
            if (!JsonHelper::GetStringValue(member_attributes, "pledge_relationship_start", pledge_relationship_start)) {
                // Fallback: try created_at (shouldn't happen with correct API call)
                JsonHelper::GetStringValue(member_attributes, "created_at", pledge_relationship_start);
            }
            // Get campaign lifetime support from member attributes
            JsonHelper::GetLongValue(member_attributes, "campaign_lifetime_support_cents", lifetime_support);
            // Get patron_status from member attributes (Currently Active)
            JsonHelper::GetStringValue(member_attributes, "patron_status", patron_status_str);
        } else {
            // Fallback: try root level (for backward compatibility)
            if (!JsonHelper::GetStringValue(response.data, "pledge_relationship_start", pledge_relationship_start)) {
                JsonHelper::GetStringValue(response.data, "created_at", pledge_relationship_start);
            }
            JsonHelper::GetLongValue(response.data, "campaign_lifetime_support_cents", lifetime_support);
            JsonHelper::GetStringValue(response.data, "patron_status", patron_status_str);
        }
        
        // Parse pledge relationship start date (Member Since)
        if (!pledge_relationship_start.empty()) {
            int year = 0, month = 0, day = 0;
            if (JsonHelper::ParseISODate(pledge_relationship_start, year, month, day)) {
                history->subscription_started_year = year;
                history->subscription_started_month = month;
                history->subscription_started_day = day;
                
                // Format human-readable date
                snprintf(history->member_since, sizeof(history->member_since), 
                        "%04d-%02d-%02d", year, month, day);
            }
        }
        
        // Set lifetime support
        history->total_support_cents = lifetime_support;
        
        // Check if member is currently active (patron_status == "active_patron")
        if (!patron_status_str.empty()) {
            is_active = (patron_status_str == "active_patron");
        }
        
        history->is_active = is_active ? 1 : 0;
        
        // Calculate months active (approximate, based on creation date)
        if (history->subscription_started_year > 0) {
            // Get current date
            time_t now = time(nullptr);
            struct tm* current_time = nullptr;
#ifdef _WIN32
            struct tm timeinfo;
            localtime_s(&timeinfo, &now);
            current_time = &timeinfo;
#else
            current_time = localtime(&now);
#endif
            
            if (current_time) {
                int current_year = current_time->tm_year + 1900;
                int current_month = current_time->tm_mon + 1;
                
                // Calculate approximate months
                int year_diff = current_year - history->subscription_started_year;
                int month_diff = current_month - history->subscription_started_month;
                history->months_active = year_diff * 12 + month_diff;
                
                // Ensure non-negative
                if (history->months_active < 0) {
                    history->months_active = 0;
                }
            }
        }
        
        SecurityUtils::LogMessage("Subscription history retrieved successfully");
        return PATREON_SUCCESS;
    }
    catch (const std::bad_alloc&) {
        SetError("Memory allocation failed");
        SecurityUtils::LogMessage("Memory allocation failed in PATREON_GetSubscriptionHistory");
        return PATREON_ERROR_MEMORY;
    }
    catch (...) {
        SetError("Unknown error occurred");
        SecurityUtils::LogMessage("Unknown error in PATREON_GetSubscriptionHistory");
        return PATREON_ERROR_UNKNOWN;
    }
}

int PATREON_GetMemberDetails(const char* access_token, PATREON_MemberDetails* member_details, int timeout_seconds) {
    try {
        // Anti-debugging and integrity checks
        Obfuscation::DeadCode1();
        if (Obfuscation::IsDebuggerPresent()) {
            Obfuscation::DeadCode2();
            return PATREON_ERROR_UNKNOWN;
        }
        if (!Obfuscation::VerifyIntegrity()) {
            Obfuscation::DeadCode3();
            return PATREON_ERROR_UNKNOWN;
        }
        
        // Anti-patching check
        if (PATREON_IsClientPatched() == 1) {
            Obfuscation::DeadCode1();
            SecurityUtils::LogMessage("Client patching detected - member details request blocked");
            return PATREON_ERROR_UNKNOWN;
        }
        
        // Verify client integrity
        if (PATREON_VerifyClientIntegrity() == 0) {
            Obfuscation::DeadCode2();
            SecurityUtils::LogMessage("Client integrity check failed - member details request blocked");
            return PATREON_ERROR_UNKNOWN;
        }
        
        Obfuscation::DeadCode2();
        
        // Input validation
        if (!ValidateInput(access_token)) {
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        if (!member_details) {
            SetError("Member details output structure is null");
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        // Initialize structure
        memset(member_details, 0, sizeof(PATREON_MemberDetails));
        
        // Get HWID for enhanced rate limiting
        char hwid_buffer[256] = {0};
        size_t hwid_len = PATREON_GetHardwareID(hwid_buffer, sizeof(hwid_buffer));
        std::string hwid_str = (hwid_len > 0) ? std::string(hwid_buffer) : "";
        
        // Enhanced rate limiting check
        std::string token_str(access_token);
        if (!SecurityUtils::CheckEnhancedRateLimit(token_str, hwid_str)) {
            SetError("Rate limit exceeded - too many requests");
            SecurityUtils::LogMessage("Rate limit exceeded for token: " + token_str.substr(0, 10) + "...");
            return PATREON_ERROR_NETWORK;
        }
        
        SecurityUtils::LogMessage("Getting member details for token: " + token_str.substr(0, 10) + "...");
        
        // Build API URL to get member information with tier and free trial fields
        // Include tiers to get title field, and user fields for account details
        Obfuscation::DeadCode3();
        std::string base_url = Obfuscation::GetBaseURL();
        std::string params = "include=memberships.currently_entitled_tiers&fields[member]=last_charge_status,patron_status,currently_entitled_amount_cents,is_free_trial&fields[tier]=title&fields[user]=created,is_email_verified,is_creator,can_see_nsfw,first_name,last_name";
        std::string url = base_url + "?" + params;
        Obfuscation::DeadCode1();
        
        // Make request
        HttpResponse response = MakePatreonRequest(url, access_token, timeout_seconds > 0 ? timeout_seconds : 30);
        
        if (!response.success) {
            if (response.status_code == 0) {
                SetError("Network connection error - unable to reach Patreon API");
                return PATREON_ERROR_NETWORK;
            }
            if (response.status_code == 401 || response.status_code == 403) {
                SetError("Invalid or expired access token");
                return PATREON_ERROR_INVALID_TOKEN;
            }
            SetError("HTTP error: " + std::to_string(response.status_code));
            return PATREON_ERROR_INVALID_RESPONSE;
        }
        
        // Parse response
        if (!ParseMemberDetails(response.data, member_details)) {
            SetError("Failed to parse member details from API response");
            return PATREON_ERROR_INVALID_RESPONSE;
        }
        
        SecurityUtils::LogMessage("Member details retrieved successfully");
        return PATREON_SUCCESS;
    }
    catch (const std::bad_alloc&) {
        SetError("Memory allocation failed");
        SecurityUtils::LogMessage("Memory allocation failed in PATREON_GetMemberDetails");
        return PATREON_ERROR_MEMORY;
    }
    catch (...) {
        SetError("Unknown error occurred");
        SecurityUtils::LogMessage("Unknown error in PATREON_GetMemberDetails");
        return PATREON_ERROR_UNKNOWN;
    }
}

int PATREON_SetServerURL(const char* server_url_param) {
    try {
        std::lock_guard<std::mutex> lock(server_url_mutex);
        
        if (server_url_param && strlen(server_url_param) > 0) {
            // Validate URL format (basic check)
            std::string url_str(server_url_param);
            if (url_str.find("http://") != 0 && url_str.find("https://") != 0) {
                SetError("Invalid server URL format - must start with http:// or https://");
                return PATREON_ERROR_INVALID_INPUT;
            }
            
            // Remove trailing slash
            if (url_str.back() == '/') {
                url_str.pop_back();
            }
            
            server_url = url_str;
            SecurityUtils::LogMessage("Server URL set to: " + server_url);
        } else {
            server_url.clear();
            SecurityUtils::LogMessage("Server URL cleared - using direct Patreon API");
        }
        
        return PATREON_SUCCESS;
    }
    catch (...) {
        SetError("Unknown error occurred");
        return PATREON_ERROR_UNKNOWN;
    }
}

size_t PATREON_GetServerURL(char* server_url_buffer, size_t buffer_size) {
    if (!server_url_buffer || buffer_size == 0) {
        return 0;
    }
    
    std::lock_guard<std::mutex> lock(server_url_mutex);
    
    if (server_url.empty()) {
        server_url_buffer[0] = '\0';
        return 0;
    }
    
    // Calculate copy size
    size_t copy_size = (server_url.length() < buffer_size - 1) ? server_url.length() : buffer_size - 1;
    
    // Safe copy with guaranteed null terminator
    SafeStringCopy(server_url_buffer, buffer_size, server_url);
    
    return copy_size;
}

int PATREON_StartOAuthFlow(const char* client_id, const char* redirect_uri, const char* scope) {
    try {
        // Input validation
        if (!client_id || strlen(client_id) == 0) {
            SetError("Client ID is required");
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        if (!redirect_uri || strlen(redirect_uri) == 0) {
            SetError("Redirect URI is required");
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        // Build OAuth2 authorization URL
        std::string auth_url = "https://www.patreon.com/oauth2/authorize";
        auth_url += "?response_type=code";
        auth_url += "&client_id=" + std::string(client_id);
        auth_url += "&redirect_uri=";
        
        // URL encode redirect_uri (simple encoding)
        std::string encoded_redirect = "";
        for (size_t i = 0; i < strlen(redirect_uri); i++) {
            char c = redirect_uri[i];
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || 
                (c >= '0' && c <= '9') || c == '-' || c == '_' || 
                c == '.' || c == '~' || c == '/' || c == ':' || c == '?') {
                encoded_redirect += c;
            } else {
                char hex[4];
                snprintf(hex, sizeof(hex), "%%%02X", (unsigned char)c);
                encoded_redirect += hex;
            }
        }
        auth_url += encoded_redirect;
        
        if (scope && strlen(scope) > 0) {
            auth_url += "&scope=";
            // URL encode scope
            for (size_t i = 0; i < strlen(scope); i++) {
                char c = scope[i];
                if (c == ' ') {
                    auth_url += "+";
                } else if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || 
                           (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
                    auth_url += c;
                } else {
                    char hex[4];
                    snprintf(hex, sizeof(hex), "%%%02X", (unsigned char)c);
                    auth_url += hex;
                }
            }
        } else {
            // Default scope
            auth_url += "&scope=identity+identity.memberships";
        }
        
        SecurityUtils::LogMessage("Starting OAuth2 flow - opening browser");
        
        // Open browser (platform-specific)
#ifdef _WIN32
        int result = OpenBrowser_Windows(auth_url);
#else
        int result = OpenBrowser_Linux(auth_url);
#endif
        
        if (result != PATREON_SUCCESS) {
            SetError("Failed to open browser");
            return result;
        }
        
        SecurityUtils::LogMessage("OAuth2 authorization URL opened in browser");
        return PATREON_SUCCESS;
    }
    catch (...) {
        SetError("Unknown error occurred");
        return PATREON_ERROR_UNKNOWN;
    }
}

int PATREON_ExchangeCodeForToken(const char* code, const char* redirect_uri, PATREON_TokenResponse* token_response, int timeout_seconds) {
    try {
        // Anti-debugging checks
        Obfuscation::DeadCode1();
        if (Obfuscation::IsDebuggerPresent()) {
            Obfuscation::DeadCode2();
            return PATREON_ERROR_UNKNOWN;
        }
        
        // Input validation
        if (!code || strlen(code) == 0) {
            SetError("Authorization code is required");
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        if (!redirect_uri || strlen(redirect_uri) == 0) {
            SetError("Redirect URI is required");
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        if (!token_response) {
            SetError("Token response structure is null");
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        // Initialize response structure
        memset(token_response, 0, sizeof(PATREON_TokenResponse));
        
        // Get server URL
        std::string server;
        {
            std::lock_guard<std::mutex> lock(server_url_mutex);
            if (server_url.empty()) {
                SetError("Server URL not set - call PATREON_SetServerURL first");
                return PATREON_ERROR_INVALID_INPUT;
            }
            server = server_url;
        }
        
        // Build server endpoint URL
        std::string endpoint = server;
        if (endpoint.back() != '/') {
            endpoint += "/";
        }
        endpoint += "oauth/exchange"; // Standard endpoint: /oauth/exchange
        
        // Build POST data (JSON)
        // Function to properly escape JSON string values
        auto escape_json_string = [](const char* str) -> std::string {
            std::ostringstream escaped;
            for (const char* p = str; *p; p++) {
                switch (*p) {
                    case '"':  escaped << "\\\""; break;
                    case '\\': escaped << "\\\\"; break;
                    case '\b': escaped << "\\b"; break;
                    case '\f': escaped << "\\f"; break;
                    case '\n': escaped << "\\n"; break;
                    case '\r': escaped << "\\r"; break;
                    case '\t': escaped << "\\t"; break;
                    default:
                        // Control characters (0x00-0x1F) must be escaped as \uXXXX
                        if (*p >= 0 && *p < 32) {
                            char hex[7];
                            std::sprintf(hex, "\\u%04x", static_cast<unsigned char>(*p));
                            escaped << hex;
                        } else {
                            escaped << *p;
                        }
                        break;
                }
            }
            return escaped.str();
        };
        
        std::ostringstream post_data;
        post_data << "{\"code\":\"" << escape_json_string(code) 
                  << "\",\"redirect_uri\":\"" << escape_json_string(redirect_uri) << "\"}";
        
        SecurityUtils::LogMessage("Exchanging authorization code for token via server");
        
        // Make POST request to server
        HttpResponse response;
        if (timeout_seconds <= 0) {
            timeout_seconds = 30; // Default 30 seconds for OAuth operations
        }
        
#ifdef _WIN32
        response = MakeServerRequest_Windows(endpoint, post_data.str(), timeout_seconds);
#else
        response = MakeServerRequest_Linux(endpoint, post_data.str(), timeout_seconds);
#endif
        
        if (!response.success) {
            if (response.status_code == 0) {
                SetError("Network error connecting to server");
                return PATREON_ERROR_NETWORK;
            }
            
            // Try to parse error_description from JSON response
            std::string error_msg = "Server returned error: " + std::to_string(response.status_code);
            std::string json = response.data;
            
            // If response data is empty, use status-based error messages
            if (json.empty()) {
                if (response.status_code == 401) {
                    error_msg = "Unauthorized - check client credentials or authorization code";
                } else if (response.status_code == 400) {
                    error_msg = "Bad request - invalid parameters";
                } else if (response.status_code == 500) {
                    error_msg = "Server error - check server logs";
                } else {
                    error_msg = "Server returned error: " + std::to_string(response.status_code);
                }
            } else {
                // Try multiple JSON parsing strategies
                bool parsed_error = false;
                
                // Strategy 1: Look for error_description field (standard OAuth2 format)
                size_t error_desc_start = json.find("\"error_description\":\"");
                if (error_desc_start != std::string::npos) {
                    error_desc_start += 21; // Length of "error_description":"
                    size_t error_desc_end = json.find("\"", error_desc_start);
                    if (error_desc_end != std::string::npos) {
                        std::string error_desc = json.substr(error_desc_start, error_desc_end - error_desc_start);
                        // Unescape JSON string (basic - handles \" and \n)
                        std::string unescaped;
                        for (size_t i = 0; i < error_desc.length(); i++) {
                            if (error_desc[i] == '\\' && i + 1 < error_desc.length()) {
                                if (error_desc[i + 1] == '"') {
                                    unescaped += '"';
                                    i++; // Skip next char
                                } else if (error_desc[i + 1] == 'n') {
                                    unescaped += '\n';
                                    i++; // Skip next char
                                } else if (error_desc[i + 1] == '\\') {
                                    unescaped += '\\';
                                    i++; // Skip next char
                                } else {
                                    unescaped += error_desc[i];
                                }
                            } else {
                                unescaped += error_desc[i];
                            }
                        }
                        if (!unescaped.empty()) {
                            error_msg = unescaped;
                            parsed_error = true;
                            
                            // Check if message mentions expiration and make it more explicit
                            std::string msg_lower = error_msg;
                            std::transform(msg_lower.begin(), msg_lower.end(), msg_lower.begin(), ::tolower);
                            if (msg_lower.find("expired") != std::string::npos && 
                                (msg_lower.find("code") != std::string::npos || msg_lower.find("authorization") != std::string::npos)) {
                                // Ensure it's clear it's the authorization code
                                if (msg_lower.find("authorization code") == std::string::npos && 
                                    msg_lower.find("authorization_code") == std::string::npos) {
                                    error_msg = "Authorization code has expired. Please get a new code.";
                                } else {
                                    // Already mentions authorization code, just ensure clarity
                                    error_msg = "Authorization code has expired. Please get a new code.";
                                }
                            }
                        }
                    }
                }
                
                // Strategy 2: If error_description not found, try "error" field
                if (!parsed_error) {
                    size_t error_start = json.find("\"error\":\"");
                    if (error_start != std::string::npos) {
                        error_start += 9; // Length of "error":"
                        size_t error_end = json.find("\"", error_start);
                        if (error_end != std::string::npos) {
                            std::string error_type = json.substr(error_start, error_end - error_start);
                            
                            // Check for expiration in error_description first
                            std::string json_lower = json;
                            std::transform(json_lower.begin(), json_lower.end(), json_lower.begin(), ::tolower);
                            
                            // Map common OAuth error codes to user-friendly messages
                            if (error_type == "invalid_grant") {
                                // Check if error_description mentions expiration
                                if (json_lower.find("expired") != std::string::npos) {
                                    error_msg = "Authorization code has expired. Please get a new code.";
                                } else if (json_lower.find("invalid") != std::string::npos) {
                                    error_msg = "Authorization code is invalid or already used. Please get a new code.";
                                } else {
                                    error_msg = "Authorization code is invalid, expired, or already used. Please get a new code.";
                                }
                            } else if (error_type == "invalid_client") {
                                error_msg = "Client ID or Client Secret is incorrect. Check your server configuration.";
                            } else if (error_type == "invalid_request") {
                                error_msg = "Invalid request. Check that redirect_uri matches exactly.";
                            } else {
                                error_msg = "OAuth error: " + error_type + " (status: " + std::to_string(response.status_code) + ")";
                            }
                            parsed_error = true;
                        }
                    }
                }
                
                // Strategy 3: Try to find "message" field as fallback
                if (!parsed_error) {
                    size_t msg_start = json.find("\"message\":\"");
                    if (msg_start != std::string::npos) {
                        msg_start += 11; // Length of "message":"
                        size_t msg_end = json.find("\"", msg_start);
                        if (msg_end != std::string::npos) {
                            error_msg = json.substr(msg_start, msg_end - msg_start);
                            parsed_error = true;
                        }
                    }
                }
                
                // If still not parsed, use status code with hint about checking server logs
                if (!parsed_error) {
                    if (response.status_code == 400) {
                        error_msg = "Bad request (400) - check server logs for details";
                    } else if (response.status_code == 401) {
                        error_msg = "Unauthorized (401) - check client credentials or authorization code";
                    } else if (response.status_code == 500) {
                        error_msg = "Server error (500) - check server logs";
                    } else {
                        error_msg = "Server returned error: " + std::to_string(response.status_code) + " - check server logs";
                    }
                }
            }
            
            SetError(error_msg);
            return PATREON_ERROR_INVALID_RESPONSE;
        }
        
        // Parse JSON response
        // Expected format: {"access_token":"...","refresh_token":"...","token_type":"Bearer","expires_in":3600,"scope":"..."}
        std::string json = response.data;
        
        // Parse access_token
        size_t token_start = json.find("\"access_token\":\"");
        if (token_start != std::string::npos) {
            token_start += 16; // Length of "access_token":"
            size_t token_end = json.find("\"", token_start);
            if (token_end != std::string::npos) {
                std::string token = json.substr(token_start, token_end - token_start);
                SafeStringCopy(token_response->access_token, sizeof(token_response->access_token), token);
            }
        }
        
        // Parse refresh_token (optional)
        size_t refresh_start = json.find("\"refresh_token\":\"");
        if (refresh_start != std::string::npos) {
            refresh_start += 17; // Length of "refresh_token":"
            size_t refresh_end = json.find("\"", refresh_start);
            if (refresh_end != std::string::npos) {
                std::string refresh = json.substr(refresh_start, refresh_end - refresh_start);
                SafeStringCopy(token_response->refresh_token, sizeof(token_response->refresh_token), refresh);
            }
        }
        
        // Parse token_type
        size_t type_start = json.find("\"token_type\":\"");
        if (type_start != std::string::npos) {
            type_start += 14; // Length of "token_type":"
            size_t type_end = json.find("\"", type_start);
            if (type_end != std::string::npos) {
                std::string type = json.substr(type_start, type_end - type_start);
                SafeStringCopy(token_response->token_type, sizeof(token_response->token_type), type);
            } else {
                SafeStringCopy(token_response->token_type, sizeof(token_response->token_type), "Bearer");
            }
        } else {
            SafeStringCopy(token_response->token_type, sizeof(token_response->token_type), "Bearer");
        }
        
        // Parse expires_in
        size_t expires_start = json.find("\"expires_in\":");
        if (expires_start != std::string::npos) {
            expires_start += 13; // Length of "expires_in":"
            size_t expires_end = json.find_first_of(",}", expires_start);
            if (expires_end != std::string::npos) {
                std::string expires_str = json.substr(expires_start, expires_end - expires_start);
                token_response->expires_in = std::atoi(expires_str.c_str());
            } else {
                token_response->expires_in = -1;
            }
        } else {
            token_response->expires_in = -1;
        }
        
        // Parse scope (optional)
        size_t scope_start = json.find("\"scope\":\"");
        if (scope_start != std::string::npos) {
            scope_start += 9; // Length of "scope":"
            size_t scope_end = json.find("\"", scope_start);
            if (scope_end != std::string::npos) {
                std::string scope = json.substr(scope_start, scope_end - scope_start);
                SafeStringCopy(token_response->scope, sizeof(token_response->scope), scope);
            }
        }
        
        if (strlen(token_response->access_token) == 0) {
            SetError("Invalid server response - access_token not found");
            return PATREON_ERROR_INVALID_RESPONSE;
        }
        
        SecurityUtils::LogMessage("Successfully exchanged code for token");
        return PATREON_SUCCESS;
    }
    catch (...) {
        SetError("Unknown error occurred");
        return PATREON_ERROR_UNKNOWN;
    }
}

int PATREON_RefreshToken(const char* refresh_token, PATREON_TokenResponse* token_response, int timeout_seconds) {
    try {
        // Anti-debugging checks
        Obfuscation::DeadCode2();
        if (Obfuscation::IsDebuggerPresent()) {
            Obfuscation::DeadCode1();
            return PATREON_ERROR_UNKNOWN;
        }
        
        // Input validation
        if (!refresh_token || strlen(refresh_token) == 0) {
            SetError("Refresh token is required");
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        if (!token_response) {
            SetError("Token response structure is null");
            return PATREON_ERROR_INVALID_INPUT;
        }
        
        // Initialize response structure
        memset(token_response, 0, sizeof(PATREON_TokenResponse));
        
        // Get server URL
        std::string server;
        {
            std::lock_guard<std::mutex> lock(server_url_mutex);
            if (server_url.empty()) {
                SetError("Server URL not set - call PATREON_SetServerURL first");
                return PATREON_ERROR_INVALID_INPUT;
            }
            server = server_url;
        }
        
        // Build server endpoint URL
        std::string endpoint = server;
        if (endpoint.back() != '/') {
            endpoint += "/";
        }
        endpoint += "oauth/refresh"; // Standard endpoint: /oauth/refresh
        
        // Build POST data (JSON)
        // Function to properly escape JSON string values (same as in ExchangeCodeForToken)
        auto escape_json_string = [](const char* str) -> std::string {
            std::ostringstream escaped;
            for (const char* p = str; *p; p++) {
                switch (*p) {
                    case '"':  escaped << "\\\""; break;
                    case '\\': escaped << "\\\\"; break;
                    case '\b': escaped << "\\b"; break;
                    case '\f': escaped << "\\f"; break;
                    case '\n': escaped << "\\n"; break;
                    case '\r': escaped << "\\r"; break;
                    case '\t': escaped << "\\t"; break;
                    default:
                        // Control characters (0x00-0x1F) must be escaped as \uXXXX
                        if (*p >= 0 && *p < 32) {
                            char hex[7];
                            std::sprintf(hex, "\\u%04x", static_cast<unsigned char>(*p));
                            escaped << hex;
                        } else {
                            escaped << *p;
                        }
                        break;
                }
            }
            return escaped.str();
        };
        
        std::ostringstream post_data;
        post_data << "{\"refresh_token\":\"" << escape_json_string(refresh_token) << "\"}";
        
        SecurityUtils::LogMessage("Refreshing access token via server");
        
        // Make POST request to server
        HttpResponse response;
        if (timeout_seconds <= 0) {
            timeout_seconds = 30; // Default 30 seconds for OAuth operations
        }
        
#ifdef _WIN32
        response = MakeServerRequest_Windows(endpoint, post_data.str(), timeout_seconds);
#else
        response = MakeServerRequest_Linux(endpoint, post_data.str(), timeout_seconds);
#endif
        
        if (!response.success) {
            if (response.status_code == 0) {
                SetError("Network error connecting to server");
                return PATREON_ERROR_NETWORK;
            }
            
            // Try to parse error_description from JSON response
            std::string error_msg = "Server returned error: " + std::to_string(response.status_code);
            std::string json = response.data;
            
            // Look for error_description in JSON response
            size_t error_desc_start = json.find("\"error_description\":\"");
            if (error_desc_start != std::string::npos) {
                error_desc_start += 21; // Length of "error_description":"
                size_t error_desc_end = json.find("\"", error_desc_start);
                if (error_desc_end != std::string::npos) {
                    std::string error_desc = json.substr(error_desc_start, error_desc_end - error_desc_start);
                    // Unescape JSON string (basic - handles \")
                    std::string unescaped;
                    for (size_t i = 0; i < error_desc.length(); i++) {
                        if (error_desc[i] == '\\' && i + 1 < error_desc.length() && error_desc[i + 1] == '"') {
                            unescaped += '"';
                            i++; // Skip next char
                        } else {
                            unescaped += error_desc[i];
                        }
                    }
                    error_msg = unescaped;
                }
            } else {
                // Try to parse "error" field as fallback
                size_t error_start = json.find("\"error\":\"");
                if (error_start != std::string::npos) {
                    error_start += 9; // Length of "error":"
                    size_t error_end = json.find("\"", error_start);
                    if (error_end != std::string::npos) {
                        std::string error_type = json.substr(error_start, error_end - error_start);
                        error_msg = "OAuth error: " + error_type + " (status: " + std::to_string(response.status_code) + ")";
                    }
                } else if (response.status_code == 401) {
                    error_msg = "Refresh token expired or invalid";
                }
            }
            
            SetError(error_msg);
            
            if (response.status_code == 401) {
                return PATREON_ERROR_INVALID_TOKEN;
            }
            return PATREON_ERROR_INVALID_RESPONSE;
        }
        
        // Parse JSON response (same format as exchange)
        std::string json = response.data;
        
        // Parse access_token
        size_t token_start = json.find("\"access_token\":\"");
        if (token_start != std::string::npos) {
            token_start += 16;
            size_t token_end = json.find("\"", token_start);
            if (token_end != std::string::npos) {
                std::string token = json.substr(token_start, token_end - token_start);
                SafeStringCopy(token_response->access_token, sizeof(token_response->access_token), token);
            }
        }
        
        // Parse refresh_token (new one, if provided)
        size_t refresh_start = json.find("\"refresh_token\":\"");
        if (refresh_start != std::string::npos) {
            refresh_start += 17;
            size_t refresh_end = json.find("\"", refresh_start);
            if (refresh_end != std::string::npos) {
                std::string refresh = json.substr(refresh_start, refresh_end - refresh_start);
                SafeStringCopy(token_response->refresh_token, sizeof(token_response->refresh_token), refresh);
            } else {
                // If no new refresh token, use the old one
                SafeStringCopy(token_response->refresh_token, sizeof(token_response->refresh_token), refresh_token);
            }
        } else {
            // If no new refresh token, use the old one
            SafeStringCopy(token_response->refresh_token, sizeof(token_response->refresh_token), refresh_token);
        }
        
        // Parse token_type
        size_t type_start = json.find("\"token_type\":\"");
        if (type_start != std::string::npos) {
            type_start += 14;
            size_t type_end = json.find("\"", type_start);
            if (type_end != std::string::npos) {
                std::string type = json.substr(type_start, type_end - type_start);
                SafeStringCopy(token_response->token_type, sizeof(token_response->token_type), type);
            } else {
                SafeStringCopy(token_response->token_type, sizeof(token_response->token_type), "Bearer");
            }
        } else {
            SafeStringCopy(token_response->token_type, sizeof(token_response->token_type), "Bearer");
        }
        
        // Parse expires_in
        size_t expires_start = json.find("\"expires_in\":");
        if (expires_start != std::string::npos) {
            expires_start += 13;
            size_t expires_end = json.find_first_of(",}", expires_start);
            if (expires_end != std::string::npos) {
                std::string expires_str = json.substr(expires_start, expires_end - expires_start);
                token_response->expires_in = std::atoi(expires_str.c_str());
            } else {
                token_response->expires_in = -1;
            }
        } else {
            token_response->expires_in = -1;
        }
        
        if (strlen(token_response->access_token) == 0) {
            SetError("Invalid server response - access_token not found");
            return PATREON_ERROR_INVALID_RESPONSE;
        }
        
        SecurityUtils::LogMessage("Successfully refreshed access token");
        return PATREON_SUCCESS;
    }
    catch (...) {
        SetError("Unknown error occurred");
        return PATREON_ERROR_UNKNOWN;
    }
}

} // extern "C"

