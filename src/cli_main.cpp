#include "../include/patreon_auth.h"
#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <fstream>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#endif

// Print usage information
void PrintUsage(const char* program_name) {
    std::cout << "Patreon Auth Middleware CLI v1.0\n";
    std::cout << "Usage: " << program_name << " [OPTIONS]\n\n";
    std::cout << "Verification Options:\n";
    std::cout << "  --user-token TOKEN      Patreon OAuth2 access token of the patron/user (required for verification)\n";
    std::cout << "                          This is the patron's access token obtained via OAuth2 flow, NOT the creator's token\n";
    std::cout << "  --tier TIER_TITLE       Check specific tier title (optional)\n";
    std::cout << "  --tier-id TIER_ID       Check specific tier ID (optional, takes precedence over --tier)\n";
    std::cout << "  --campaign CAMPAIGN_ID  Check specific campaign ID (optional)\n";
    std::cout << "  --timeout SECONDS       Network timeout in seconds (default: 30)\n";
    std::cout << "  --info                  Get detailed member information (JSON)\n";
    std::cout << "  --history               Get subscription history and tenure\n";
    std::cout << "  --details               Get member details (tier, subscription type, free/paid status)\n\n";
    std::cout << "OAuth2 Options:\n";
    std::cout << "  --server-url URL        Set server URL for OAuth2 operations\n";
    std::cout << "  --oauth-start CLIENT_ID REDIRECT_URI [SCOPE]\n";
    std::cout << "                          Start OAuth2 flow (opens browser)\n";
    std::cout << "  --oauth-exchange CODE REDIRECT_URI\n";
    std::cout << "                          Exchange authorization code for access token\n";
    std::cout << "  --oauth-refresh REFRESH_TOKEN\n";
    std::cout << "                          Refresh access token using refresh token\n\n";
    std::cout << "General Options:\n";
    std::cout << "  --help                  Show this help message\n";
    std::cout << "  --version               Show version information\n\n";
    std::cout << "Examples:\n";
    std::cout << "  # Set server URL and start OAuth2 flow\n";
    std::cout << "  " << program_name << " --server-url https://api.example.com --oauth-start CLIENT_ID http://localhost:8080/callback\n";
    std::cout << "  # Exchange code for token\n";
    std::cout << "  " << program_name << " --server-url https://api.example.com --oauth-exchange CODE http://localhost:8080/callback\n";
    std::cout << "  # Verify with patron's/user's access token (obtained via OAuth2)\n";
    std::cout << "  " << program_name << " --user-token PATRON_ACCESS_TOKEN\n";
    std::cout << "  " << program_name << " --user-token PATRON_ACCESS_TOKEN --tier \"Tier Name\"\n";
    std::cout << "  " << program_name << " --user-token PATRON_ACCESS_TOKEN --tier-id 12345\n";
    std::cout << "  " << program_name << " --user-token PATRON_ACCESS_TOKEN --info\n";
    std::cout << "  " << program_name << " --user-token PATRON_ACCESS_TOKEN --history\n";
    std::cout << "  " << program_name << " --user-token PATRON_ACCESS_TOKEN --details\n\n";
    std::cout << "Exit codes:\n";
    std::cout << "  0  - Success\n";
    std::cout << "  1  - Member is not active or not subscribed\n";
    std::cout << "  2  - Invalid input parameters\n";
    std::cout << "  3  - Network error\n";
    std::cout << "  4  - Invalid or expired token\n";
    std::cout << "  5  - Invalid API response\n";
    std::cout << "  6  - Memory allocation error\n";
    std::cout << "  99 - Unknown error\n";
}

// Print version information
void PrintVersion() {
    std::cout << "Patreon Auth Middleware CLI v1.0\n";
    std::cout << "Universal middleware for Patreon subscription verification\n";
    std::cout << "Copyright (c) 2024\n";
}

// Convert error code to exit code
int ErrorCodeToExitCode(int error_code) {
    switch (error_code) {
    case PATREON_SUCCESS:
        return 0;
    case PATREON_ERROR_NOT_MEMBER:
        return 1;
    case PATREON_ERROR_INVALID_INPUT:
        return 2;
    case PATREON_ERROR_NETWORK:
    case PATREON_ERROR_TIMEOUT:
        return 3;
    case PATREON_ERROR_INVALID_TOKEN:
        return 4;
    case PATREON_ERROR_INVALID_RESPONSE:
        return 5;
    case PATREON_ERROR_MEMORY:
        return 6;
    default:
        return 99;
    }
}

// Logging callback function
void LogCallback(const char* message, void* user_data) {
    if (message) {
        std::cerr << "[LOG] " << message << std::endl;
    }
}

// Main function
int main(int argc, char* argv[]) {
    // Set up logging callback to see debug messages
    PATREON_SetLogCallback(LogCallback, nullptr);
    
    // Parse command line arguments
    const char* access_token = nullptr;
    const char* tier_title = nullptr;
    const char* tier_id = nullptr;
    const char* campaign_id = nullptr;
    int timeout_seconds = 30;
    bool get_info = false;
    bool get_history = false;
    bool get_details = false;
    
    // OAuth2 options
    const char* server_url = nullptr;
    const char* oauth_client_id = nullptr;
    const char* oauth_redirect_uri = nullptr;
    const char* oauth_scope = nullptr;
    const char* oauth_code = nullptr;
    const char* oauth_refresh_token = nullptr;
    bool oauth_start = false;
    bool oauth_exchange = false;
    bool oauth_refresh = false;
    
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 2;
    }
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-v") == 0) {
            PrintVersion();
            return 0;
        }
        else if (strcmp(argv[i], "--server-url") == 0) {
            if (i + 1 < argc) {
                server_url = argv[++i];
            } else {
                std::cerr << "Error: --server-url requires a value\n";
                return 2;
            }
        }
        else if (strcmp(argv[i], "--oauth-start") == 0) {
            oauth_start = true;
            if (i + 1 < argc) {
                oauth_client_id = argv[++i];
            } else {
                std::cerr << "Error: --oauth-start requires CLIENT_ID\n";
                return 2;
            }
            if (i + 1 < argc) {
                oauth_redirect_uri = argv[++i];
            } else {
                std::cerr << "Error: --oauth-start requires REDIRECT_URI\n";
                return 2;
            }
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                oauth_scope = argv[++i];
            }
        }
        else if (strcmp(argv[i], "--oauth-exchange") == 0) {
            oauth_exchange = true;
            if (i + 1 < argc) {
                oauth_code = argv[++i];
            } else {
                std::cerr << "Error: --oauth-exchange requires CODE\n";
                return 2;
            }
            if (i + 1 < argc) {
                oauth_redirect_uri = argv[++i];
            } else {
                std::cerr << "Error: --oauth-exchange requires REDIRECT_URI\n";
                return 2;
            }
        }
        else if (strcmp(argv[i], "--oauth-refresh") == 0) {
            oauth_refresh = true;
            if (i + 1 < argc) {
                oauth_refresh_token = argv[++i];
            } else {
                std::cerr << "Error: --oauth-refresh requires REFRESH_TOKEN\n";
                return 2;
            }
        }
        else if (strcmp(argv[i], "--user-token") == 0 || strcmp(argv[i], "--token") == 0) {
            // Accept both --user-token and --token for backward compatibility, but prefer --user-token
            if (i + 1 < argc) {
                access_token = argv[++i];
            } else {
                std::cerr << "Error: --user-token requires a value\n";
                std::cerr << "Note: --user-token expects the patron's/user's OAuth2 access token, not the creator's token\n";
                return 2;
            }
        }
        else if (strcmp(argv[i], "--tier") == 0) {
            if (i + 1 < argc) {
                tier_title = argv[++i];
                if (!tier_title || strlen(tier_title) == 0) {
                    std::cerr << "Error: Invalid tier title\n";
                    return 2;
                }
            } else {
                std::cerr << "Error: --tier requires a value\n";
                return 2;
            }
        }
        else if (strcmp(argv[i], "--tier-id") == 0) {
            if (i + 1 < argc) {
                tier_id = argv[++i];
                if (!tier_id || strlen(tier_id) == 0) {
                    std::cerr << "Error: Invalid tier ID\n";
                    return 2;
                }
            } else {
                std::cerr << "Error: --tier-id requires a value\n";
                return 2;
            }
        }
        else if (strcmp(argv[i], "--campaign") == 0) {
            if (i + 1 < argc) {
                campaign_id = argv[++i];
            } else {
                std::cerr << "Error: --campaign requires a value\n";
                return 2;
            }
        }
        else if (strcmp(argv[i], "--timeout") == 0) {
            if (i + 1 < argc) {
                timeout_seconds = atoi(argv[++i]);
                if (timeout_seconds <= 0) {
                    std::cerr << "Error: Invalid timeout value\n";
                    return 2;
                }
            } else {
                std::cerr << "Error: --timeout requires a value\n";
                return 2;
            }
        }
        else if (strcmp(argv[i], "--info") == 0) {
            get_info = true;
        }
        else if (strcmp(argv[i], "--history") == 0) {
            get_history = true;
        }
        else if (strcmp(argv[i], "--details") == 0) {
            get_details = true;
        }
        else {
            std::cerr << "Error: Unknown option '" << argv[i] << "'\n";
            std::cerr << "Use --help for usage information\n";
            return 2;
        }
    }
    
    // Set server URL if provided
    if (server_url) {
        int result = PATREON_SetServerURL(server_url);
        if (result != PATREON_SUCCESS) {
            char error_msg[512] = {0};
            PATREON_GetLastError(error_msg, sizeof(error_msg));
            std::cerr << "Error setting server URL: " << error_msg << std::endl;
            return ErrorCodeToExitCode(result);
        }
        std::cout << "Server URL set to: " << server_url << std::endl;
        std::cout << std::endl;
    }
    
    // Handle OAuth2 operations
    if (oauth_start) {
        int result = PATREON_StartOAuthFlow(oauth_client_id, oauth_redirect_uri, oauth_scope);
        if (result == PATREON_SUCCESS) {
            std::cout << std::endl;
            std::cout << "OAuth2 authorization URL opened in browser." << std::endl;
            std::cout << "After authorization, use --oauth-exchange with the code from redirect URI." << std::endl;
            std::cout << std::endl;
            return 0;
        } else {
            char error_msg[512] = {0};
            PATREON_GetLastError(error_msg, sizeof(error_msg));
            std::cerr << "\nError starting OAuth2 flow: " << error_msg << std::endl;
            std::cerr << std::endl;
            return ErrorCodeToExitCode(result);
        }
    }
    
    if (oauth_exchange) {
        if (!server_url) {
            std::cerr << "Error: --server-url is required for --oauth-exchange" << std::endl;
            return 2;
        }
        PATREON_TokenResponse token_response;
        int result = PATREON_ExchangeCodeForToken(oauth_code, oauth_redirect_uri, &token_response, timeout_seconds);
        if (result == PATREON_SUCCESS) {
            std::cout << "\nCode exchange successful" << std::endl;
            std::cout << "Access Token: " << token_response.access_token << std::endl;
            std::cout << std::endl;
            
            // Save token to lastUserToken file in executable directory
            std::string token_file_path;
#ifdef _WIN32
            // Get executable directory
            char exe_path[MAX_PATH];
            if (GetModuleFileNameA(nullptr, exe_path, MAX_PATH) > 0) {
                std::string exe_dir(exe_path);
                size_t last_slash = exe_dir.find_last_of("\\/");
                if (last_slash != std::string::npos) {
                    exe_dir = exe_dir.substr(0, last_slash + 1);
                }
                token_file_path = exe_dir + "lastUserToken";
            } else {
                token_file_path = "lastUserToken"; // Fallback to current directory
            }
#else
            // Get executable directory on Linux
            char exe_path[1024];
            ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
            if (len != -1) {
                exe_path[len] = '\0';
                std::string exe_dir(exe_path);
                size_t last_slash = exe_dir.find_last_of("/");
                if (last_slash != std::string::npos) {
                    exe_dir = exe_dir.substr(0, last_slash + 1);
                }
                token_file_path = exe_dir + "lastUserToken";
            } else {
                token_file_path = "lastUserToken"; // Fallback to current directory
            }
#endif
            
            // Write tokens to file (access_token and refresh_token)
            std::ofstream token_file(token_file_path);
            if (token_file.is_open()) {
                token_file << "access_token=" << token_response.access_token << "\n";
                if (strlen(token_response.refresh_token) > 0) {
                    token_file << "refresh_token=" << token_response.refresh_token << "\n";
                }
                token_file.close();
                std::cout << "Tokens saved to: " << token_file_path << std::endl;
                std::cout << std::endl;
            } else {
                std::cerr << "\nWarning: Could not save tokens to file: " << token_file_path << std::endl;
                std::cerr << std::endl;
            }
            
            // Automatically verify if user is active
            std::cout << "Verifying member status..." << std::endl;
            int verify_result = PATREON_VerifyMember(token_response.access_token, nullptr, nullptr, nullptr, timeout_seconds > 0 ? timeout_seconds : 30);
            
            std::cout << std::endl;
            if (verify_result == PATREON_SUCCESS) {
                std::cout << "Member is ACTIVE" << std::endl;
            } else if (verify_result == PATREON_ERROR_NOT_MEMBER) {
                char verify_error[512] = {0};
                PATREON_GetLastError(verify_error, sizeof(verify_error));
                if (strlen(verify_error) > 0) {
                    std::cout << "Member is NOT ACTIVE: " << verify_error << std::endl;
                } else {
                    std::cout << "Member is NOT ACTIVE or not subscribed" << std::endl;
                }
            } else {
                char verify_error[512] = {0};
                PATREON_GetLastError(verify_error, sizeof(verify_error));
                std::cout << "Could not verify status: " << verify_error << std::endl;
                
                // Provide helpful context for token errors
                if (verify_result == PATREON_ERROR_INVALID_TOKEN) {
                    std::cout << std::endl;
                    std::cout << "Note: This might mean:" << std::endl;
                    std::cout << "  - Token doesn't have required scopes (identity.memberships)" << std::endl;
                    std::cout << "  - User is not a patron of any creator" << std::endl;
                    std::cout << "  - Token is expired or invalid" << std::endl;
                    std::cout << "  - Token is a creator token, not a patron token" << std::endl;
                }
            }
            std::cout << std::endl;
            
            return 0;
        } else {
            char error_msg[512] = {0};
            PATREON_GetLastError(error_msg, sizeof(error_msg));
            std::cerr << "\nError exchanging code: " << error_msg << std::endl;
            std::cerr << std::endl;
            return ErrorCodeToExitCode(result);
        }
    }
    
    if (oauth_refresh) {
        if (!server_url) {
            std::cerr << "Error: --server-url is required for --oauth-refresh" << std::endl;
            return 2;
        }
        PATREON_TokenResponse token_response;
        int result = PATREON_RefreshToken(oauth_refresh_token, &token_response, timeout_seconds);
        if (result == PATREON_SUCCESS) {
            std::cout << "\nToken refresh successful" << std::endl;
            std::cout << "Access Token: " << token_response.access_token << std::endl;
            std::cout << std::endl;
            
            // Save token to lastUserToken file in executable directory
            std::string token_file_path;
#ifdef _WIN32
            // Get executable directory
            char exe_path[MAX_PATH];
            if (GetModuleFileNameA(nullptr, exe_path, MAX_PATH) > 0) {
                std::string exe_dir(exe_path);
                size_t last_slash = exe_dir.find_last_of("\\/");
                if (last_slash != std::string::npos) {
                    exe_dir = exe_dir.substr(0, last_slash + 1);
                }
                token_file_path = exe_dir + "lastUserToken";
            } else {
                token_file_path = "lastUserToken"; // Fallback to current directory
            }
#else
            // Get executable directory on Linux
            char exe_path[1024];
            ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
            if (len != -1) {
                exe_path[len] = '\0';
                std::string exe_dir(exe_path);
                size_t last_slash = exe_dir.find_last_of("/");
                if (last_slash != std::string::npos) {
                    exe_dir = exe_dir.substr(0, last_slash + 1);
                }
                token_file_path = exe_dir + "lastUserToken";
            } else {
                token_file_path = "lastUserToken"; // Fallback to current directory
            }
#endif
            
            std::ofstream token_file(token_file_path);
            if (token_file.is_open()) {
                token_file << "access_token=" << token_response.access_token << "\n";
                if (strlen(token_response.refresh_token) > 0) {
                    token_file << "refresh_token=" << token_response.refresh_token << "\n";
                }
                token_file.close();
                std::cout << "Tokens saved to: " << token_file_path << std::endl;
                std::cout << std::endl;
            } else {
                std::cerr << "\nWarning: Could not save tokens to file: " << token_file_path << std::endl;
                std::cerr << std::endl;
            }
            
            // Automatically verify if user is active
            std::cout << "Verifying member status..." << std::endl;
            int verify_result = PATREON_VerifyMember(token_response.access_token, nullptr, nullptr, nullptr, timeout_seconds > 0 ? timeout_seconds : 30);
            
            std::cout << std::endl;
            if (verify_result == PATREON_SUCCESS) {
                std::cout << "Member is ACTIVE" << std::endl;
            } else if (verify_result == PATREON_ERROR_NOT_MEMBER) {
                char verify_error[512] = {0};
                PATREON_GetLastError(verify_error, sizeof(verify_error));
                if (strlen(verify_error) > 0) {
                    std::cout << "Member is NOT ACTIVE: " << verify_error << std::endl;
                } else {
                    std::cout << "Member is NOT ACTIVE or not subscribed" << std::endl;
                }
            } else {
                char verify_error[512] = {0};
                PATREON_GetLastError(verify_error, sizeof(verify_error));
                std::cout << "Could not verify status: " << verify_error << std::endl;
                
                // Provide helpful context for token errors
                if (verify_result == PATREON_ERROR_INVALID_TOKEN) {
                    std::cout << std::endl;
                    std::cout << "Note: This might mean:" << std::endl;
                    std::cout << "  - Token doesn't have required scopes (identity.memberships)" << std::endl;
                    std::cout << "  - User is not a patron of any creator" << std::endl;
                    std::cout << "  - Token is expired or invalid" << std::endl;
                    std::cout << "  - Token is a creator token, not a patron token" << std::endl;
                }
            }
            std::cout << std::endl;
            
            return 0;
        } else {
            char error_msg[512] = {0};
            PATREON_GetLastError(error_msg, sizeof(error_msg));
            std::cerr << "\nError refreshing token: " << error_msg << std::endl;
            std::cerr << std::endl;
            return ErrorCodeToExitCode(result);
        }
    }
    
    // Validate required parameters for verification operations
    // Check if verification flags are set without token
    bool needs_token = (tier_title != nullptr) || (tier_id != nullptr) || (campaign_id != nullptr) || get_info || get_history || get_details;
    
    if (!access_token && !oauth_start && !oauth_exchange && !oauth_refresh) {
        if (needs_token) {
            std::cerr << "Error: --user-token is required when using --tier, --tier-id, --campaign, --info, --history, or --details\n";
        } else {
            std::cerr << "Error: --user-token is required for verification operations\n";
        }
        std::cerr << "Note: --user-token expects the patron's/user's OAuth2 access token, not the creator's token\n";
        std::cerr << "Use --help for usage information\n";
        return 2;
    }
    
    if (!access_token) {
        // OAuth operations don't need token
        return 0;
    }
    
    // Validate token format (basic check)
    if (strlen(access_token) == 0 || strlen(access_token) > 2048) {
        std::cerr << "Error: Invalid token format\n";
        return 2;
    }
    
    // Execute the appropriate function
    int result;
    
    if (get_history) {
        // Get subscription history
        PATREON_SubscriptionHistory history;
        result = PATREON_GetSubscriptionHistory(access_token, &history, timeout_seconds);
        
        if (result == PATREON_SUCCESS) {
            std::cout << std::endl;
            std::cout << "=== Subscription History ===" << std::endl;
            std::cout << std::endl;
            std::cout << "Member Since: " << history.member_since << std::endl;
            if (history.subscription_started_year > 0) {
                std::cout << "Subscription Started: " << history.subscription_started_year 
                         << "-" << (history.subscription_started_month < 10 ? "0" : "") 
                         << history.subscription_started_month 
                         << "-" << (history.subscription_started_day < 10 ? "0" : "") 
                         << history.subscription_started_day << std::endl;
            }
            std::cout << "Months Active: " << history.months_active << std::endl;
            std::cout << "Total Support: $" << (history.total_support_cents / 100.0) << std::endl;
            std::cout << "Currently Active: " << (history.is_active ? "Yes" : "No") << std::endl;
            std::cout << std::endl;
            return 0;
        } else {
            char error_msg[512] = {0};
            size_t error_len = PATREON_GetLastError(error_msg, sizeof(error_msg));
            
            // Provide fallback error message if GetLastError returns empty
            std::cerr << std::endl;
            if (error_len == 0 || strlen(error_msg) == 0) {
                switch (result) {
                    case PATREON_ERROR_INVALID_TOKEN:
                        std::cerr << "Error: Invalid or expired access token" << std::endl;
                        break;
                    case PATREON_ERROR_NETWORK:
                        std::cerr << "Error: Network connection error - unable to reach Patreon API" << std::endl;
                        break;
                    case PATREON_ERROR_INVALID_INPUT:
                        std::cerr << "Error: Invalid input parameters" << std::endl;
                        break;
                    case PATREON_ERROR_INVALID_RESPONSE:
                        std::cerr << "Error: Invalid API response" << std::endl;
                        break;
                    case PATREON_ERROR_MEMORY:
                        std::cerr << "Error: Memory allocation error" << std::endl;
                        break;
                    default:
                        std::cerr << "Error: Unknown error occurred (code: " << result << ")" << std::endl;
                        break;
                }
            } else {
                std::cerr << "Error: " << error_msg << std::endl;
            }
            std::cerr << std::endl;
            return ErrorCodeToExitCode(result);
        }
    } else if (get_info) {
        // Get detailed member information
        char member_info[8192] = {0};
        result = PATREON_GetMemberInfo(access_token, member_info, sizeof(member_info), timeout_seconds);
        
        if (result == PATREON_SUCCESS) {
            std::cout << std::endl;
            std::cout << member_info << std::endl;
            std::cout << std::endl;
            return 0;
        } else {
            char error_msg[512] = {0};
            size_t error_len = PATREON_GetLastError(error_msg, sizeof(error_msg));
            
            // Provide fallback error message if GetLastError returns empty
            std::cerr << std::endl;
            if (error_len == 0 || strlen(error_msg) == 0) {
                switch (result) {
                    case PATREON_ERROR_INVALID_TOKEN:
                        std::cerr << "Error: Invalid or expired access token" << std::endl;
                        break;
                    case PATREON_ERROR_NETWORK:
                        std::cerr << "Error: Network connection error - unable to reach Patreon API" << std::endl;
                        break;
                    case PATREON_ERROR_INVALID_INPUT:
                        std::cerr << "Error: Invalid input parameters" << std::endl;
                        break;
                    case PATREON_ERROR_INVALID_RESPONSE:
                        std::cerr << "Error: Invalid API response" << std::endl;
                        break;
                    case PATREON_ERROR_MEMORY:
                        std::cerr << "Error: Memory allocation error" << std::endl;
                        break;
                    default:
                        std::cerr << "Error: Unknown error occurred (code: " << result << ")" << std::endl;
                        break;
                }
            } else {
                std::cerr << "Error: " << error_msg << std::endl;
            }
            std::cerr << std::endl;
            return ErrorCodeToExitCode(result);
        }
    } else if (get_details) {
        // Get member details
        PATREON_MemberDetails details;
        result = PATREON_GetMemberDetails(access_token, &details, timeout_seconds);
        
        if (result == PATREON_SUCCESS) {
            std::cout << std::endl;
            std::cout << "=== Member Details ===" << std::endl;
            std::cout << std::endl;
            std::cout << "Subscription Type: " << details.subscription_type << std::endl;
            std::cout << "Is Free Tier Subscriber: " << (details.is_free_tier ? "Yes" : "No") << std::endl;
            std::cout << "Is Free TRIAL Subscriber: " << (details.is_free_trial ? "Yes" : "No") << std::endl;
            
            // Display active tiers (all active tiers from currently_entitled_tiers)
            if (details.tier_id == -1) {
                // No tier found
                std::cout << "Current Active Tiers: (nici un tier)" << std::endl;
                std::cout << "Tier IDs: -1" << std::endl;
            } else {
                // Parse tier_description which contains "Title1, Title2 |IDS| ID1, ID2"
                std::string tier_desc_str(details.tier_description);
                size_t ids_separator = tier_desc_str.find(" |IDS| ");
                
                if (ids_separator != std::string::npos) {
                    // Extract titles (before |IDS|)
                    std::string titles = tier_desc_str.substr(0, ids_separator);
                    // Extract IDs (after |IDS|)
                    std::string ids = tier_desc_str.substr(ids_separator + 7);
                    
                    if (!titles.empty()) {
                        std::cout << "Current Active Tiers: " << titles << std::endl;
                    } else {
                        std::cout << "Current Active Tiers: (titles not available)" << std::endl;
                    }
                    
                    if (!ids.empty()) {
                        std::cout << "Tier IDs: " << ids << std::endl;
                    }
                } else {
                    // Fallback: no separator, might be just titles or just IDs
                    if (strlen(details.tier_description) > 0) {
                        std::cout << "Current Active Tiers: " << details.tier_description << std::endl;
                        if (details.tier_id > 0) {
                            std::cout << "Tier IDs: " << details.tier_id << std::endl;
                        }
                    } else {
                        std::cout << "Current Active Tiers: (not available)" << std::endl;
                    }
                }
            }
            
            // Display amount with clear explanation
            if (details.currently_entitled_amount_cents > 0) {
                std::cout << "Current Monthly Amount: $" << (details.currently_entitled_amount_cents / 100.0) 
                          << " (amount member is currently entitled to pay per month)" << std::endl;
            } else {
                std::cout << "Current Monthly Amount: $0.00 (Free tier)" << std::endl;
            }
            
            // Display user account details
            if (strlen(details.first_name) > 0 || strlen(details.last_name) > 0) {
                std::cout << "Name: " << details.first_name;
                if (strlen(details.last_name) > 0) {
                    if (strlen(details.first_name) > 0) {
                        std::cout << " ";
                    }
                    std::cout << details.last_name;
                }
                std::cout << std::endl;
            }
            if (strlen(details.created) > 0) {
                std::cout << "Account Created: " << details.created << std::endl;
            }
            std::cout << "Email Verified: " << (details.is_email_verified ? "Yes" : "No") << std::endl;
            std::cout << "Is Creator: " << (details.is_creator ? "Yes" : "No") << std::endl;
            std::cout << "Can See NSFW: " << (details.can_see_nsfw ? "Yes" : "No") << std::endl;
            
            std::cout << std::endl;
            return 0;
        } else {
            char error_msg[512] = {0};
            size_t error_len = PATREON_GetLastError(error_msg, sizeof(error_msg));
            
            std::cerr << std::endl;
            std::cerr << std::endl;
            if (error_len == 0 || strlen(error_msg) == 0) {
                switch (result) {
                    case PATREON_ERROR_INVALID_TOKEN:
                        std::cerr << "Error: Invalid or expired access token" << std::endl;
                        break;
                    case PATREON_ERROR_NETWORK:
                        std::cerr << "Error: Network connection error - unable to reach Patreon API" << std::endl;
                        break;
                    case PATREON_ERROR_INVALID_INPUT:
                        std::cerr << "Error: Invalid input parameters" << std::endl;
                        break;
                    case PATREON_ERROR_INVALID_RESPONSE:
                        std::cerr << "Error: Invalid API response" << std::endl;
                        break;
                    case PATREON_ERROR_MEMORY:
                        std::cerr << "Error: Memory allocation error" << std::endl;
                        break;
                    default:
                        std::cerr << "Error: Unknown error occurred (code: " << result << ")" << std::endl;
                        break;
                }
            } else {
                std::cerr << "Error: " << error_msg << std::endl;
            }
            std::cerr << std::endl;
            return ErrorCodeToExitCode(result);
        }
    } else {
        // Verify member status
        result = PATREON_VerifyMember(access_token, campaign_id, tier_title, tier_id, timeout_seconds);
        
        if (result == PATREON_SUCCESS) {
            std::cout << std::endl;
            std::cout << "SUCCESS: Member is active" << std::endl;
            std::cout << std::endl;
            return 0;
        } else {
            std::cout << std::endl;
            char error_msg[512] = {0};
            size_t error_len = PATREON_GetLastError(error_msg, sizeof(error_msg));
            
            if (result == PATREON_ERROR_NOT_MEMBER) {
                // Check if error message provides more context
                if (error_len > 0 && strlen(error_msg) > 0) {
                    std::string msg(error_msg);
                    if (msg.find("not subscribed") != std::string::npos || 
                        msg.find("not subscribed to any creator") != std::string::npos) {
                        std::cout << "INACTIVE: " << error_msg << std::endl;
                    } else {
                        std::cout << "INACTIVE: Member is not subscribed or subscription is not active" << std::endl;
                        if (error_len > 0 && strlen(error_msg) > 0) {
                            std::cout << "Details: " << error_msg << std::endl;
                        }
                    }
                } else {
                    std::cout << "INACTIVE: Member is not subscribed or subscription is not active" << std::endl;
                }
            } else {
                // Provide fallback error message if GetLastError returns empty
                if (error_len == 0 || strlen(error_msg) == 0) {
                    switch (result) {
                        case PATREON_ERROR_INVALID_TOKEN:
                            std::cerr << "ERROR: Invalid or expired access token" << std::endl;
                            std::cerr << std::endl;
                            std::cerr << "Note: Make sure you're using a patron's access token (obtained via OAuth2), not a creator token." << std::endl;
                            break;
                        case PATREON_ERROR_NETWORK:
                            std::cerr << "ERROR: Network connection error - unable to reach Patreon API" << std::endl;
                            break;
                        case PATREON_ERROR_INVALID_INPUT:
                            std::cerr << "ERROR: Invalid input parameters" << std::endl;
                            break;
                        case PATREON_ERROR_INVALID_RESPONSE:
                            std::cerr << "ERROR: Invalid API response" << std::endl;
                            std::cerr << std::endl;
                            std::cerr << "Note: This might indicate the API response format changed or the token doesn't have required scopes." << std::endl;
                            break;
                        case PATREON_ERROR_MEMORY:
                            std::cerr << "ERROR: Memory allocation error" << std::endl;
                            break;
                        default:
                            std::cerr << "ERROR: Unknown error occurred (code: " << result << ")" << std::endl;
                            break;
                    }
                } else {
                    std::cerr << "ERROR: " << error_msg << std::endl;
                    if (result == PATREON_ERROR_INVALID_TOKEN) {
                        std::cerr << std::endl;
                        std::cerr << "Note: Make sure you're using a patron's access token (obtained via OAuth2), not a creator token." << std::endl;
                    }
                }
            }
            std::cerr << std::endl;
            
            return ErrorCodeToExitCode(result);
        }
    }
}

