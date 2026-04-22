#ifndef PATREON_AUTH_H
#define PATREON_AUTH_H

#ifdef _WIN32
    #ifdef PATREON_AUTH_EXPORTS
        #define PATREON_AUTH_API __declspec(dllexport)
    #elif defined(PATREON_AUTH_STATIC) || defined(PATREON_AUTH_BUILDING)
        #define PATREON_AUTH_API
    #else
        #define PATREON_AUTH_API __declspec(dllimport)
    #endif
#else
    #define PATREON_AUTH_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Error codes
#define PATREON_SUCCESS 0
#define PATREON_ERROR_INVALID_TOKEN -1
#define PATREON_ERROR_NETWORK -2
#define PATREON_ERROR_TIMEOUT -3
#define PATREON_ERROR_INVALID_RESPONSE -4
#define PATREON_ERROR_NOT_MEMBER -5
#define PATREON_ERROR_INVALID_INPUT -6
#define PATREON_ERROR_MEMORY -7
#define PATREON_ERROR_UNKNOWN -99

// Subscription status
#define PATREON_STATUS_ACTIVE 1
#define PATREON_STATUS_INACTIVE 0

/**
 * Verifies if a user is an active Patreon member
 * 
 * @param access_token Patron's/user's OAuth2 access token (null-terminated string). 
 *                     This is the token obtained via OAuth2 flow that identifies the patron, 
 *                     NOT the creator's/client token. Obtained when a patron authorizes your application.
 * @param campaign_id Optional campaign ID to check specific tier (can be NULL)
 * @param tier_title Optional tier title to check (can be NULL to check any tier)
 * @param tier_id Optional tier ID to check (can be NULL, takes precedence over tier_title if both are provided)
 * @param timeout_seconds Network timeout in seconds (default: 10 if 0)
 * @return PATREON_SUCCESS (0) if member is active, negative error code otherwise
 */
PATREON_AUTH_API int PATREON_VerifyMember(const char* access_token, const char* campaign_id, const char* tier_title, const char* tier_id, int timeout_seconds);

/**
 * Gets detailed member information
 * 
 * @param access_token Patron's/user's OAuth2 access token. This is the token obtained via OAuth2 
 *                     flow that identifies the patron, NOT the creator's/client token.
 * @param member_info Output buffer for JSON response (must be pre-allocated)
 * @param buffer_size Size of member_info buffer
 * @param timeout_seconds Network timeout in seconds (default: 10 if 0)
 * @return PATREON_SUCCESS (0) on success, negative error code otherwise
 */
PATREON_AUTH_API int PATREON_GetMemberInfo(const char* access_token, char* member_info, size_t buffer_size, int timeout_seconds);

/**
 * Checks if user has access to a specific tier
 * 
 * @param access_token Patron's/user's OAuth2 access token. This is the token obtained via OAuth2 
 *                     flow that identifies the patron, NOT the creator's/client token.
 * @param tier_title Tier title to check
 * @param timeout_seconds Network timeout in seconds (default: 10 if 0)
 * @return PATREON_STATUS_ACTIVE (1) if has access, PATREON_STATUS_INACTIVE (0) if not, negative on error
 */
PATREON_AUTH_API int PATREON_CheckTierAccess(const char* access_token, const char* tier_title, int timeout_seconds);

/**
 * Gets the last error message (thread-safe)
 * 
 * @param error_buffer Output buffer for error message
 * @param buffer_size Size of error_buffer
 * @return Length of error message copied
 */
PATREON_AUTH_API size_t PATREON_GetLastError(char* error_buffer, size_t buffer_size);

/**
 * Gets the Hardware ID (HWID) of the current machine
 * 
 * @param hwid_buffer Output buffer for HWID (must be pre-allocated)
 * @param buffer_size Size of hwid_buffer
 * @return Length of HWID copied, 0 on error
 */
PATREON_AUTH_API size_t PATREON_GetHardwareID(char* hwid_buffer, size_t buffer_size);

/**
 * Signs a request with HMAC for server verification
 * 
 * @param data Data to sign (null-terminated string)
 * @param secret Secret key for signing (null-terminated string)
 * @param signature_buffer Output buffer for signature (must be pre-allocated, at least 65 bytes for hex)
 * @param buffer_size Size of signature_buffer
 * @return PATREON_SUCCESS (0) on success, negative error code otherwise
 */
PATREON_AUTH_API int PATREON_SignRequest(const char* data, const char* secret, char* signature_buffer, size_t buffer_size);

/**
 * Sets logging callback function (optional)
 * 
 * @param callback Function pointer that receives log messages (can be NULL to disable)
 * @param user_data User data passed to callback
 * @return PATREON_SUCCESS (0) on success
 */
typedef void (*PATREON_LogCallback)(const char* message, void* user_data);
PATREON_AUTH_API int PATREON_SetLogCallback(PATREON_LogCallback callback, void* user_data);

/**
 * Checks if token needs refresh (based on expiration)
 * 
 * @param access_token Patreon OAuth2 access token
 * @return 1 if token needs refresh, 0 if still valid, negative on error
 */
PATREON_AUTH_API int PATREON_TokenNeedsRefresh(const char* access_token);

/**
 * Verifies client integrity (anti-patching check)
 * Performs comprehensive checks for code modification, hooks, and patching tools
 * 
 * @return 1 if client is intact, 0 if patching detected
 */
PATREON_AUTH_API int PATREON_VerifyClientIntegrity();

/**
 * Quick check if client has been patched
 * 
 * @return 1 if patched, 0 if not patched
 */
PATREON_AUTH_API int PATREON_IsClientPatched();

// License management policy
#define PATREON_LICENSE_POLICY_BLOCK 0      // Block access if HWID doesn't match
#define PATREON_LICENSE_POLICY_TRANSFER 1   // Allow transfer to new device

// License status
#define PATREON_LICENSE_STATUS_NEW 0        // New device, needs registration
#define PATREON_LICENSE_STATUS_VALID 1      // HWID matches, access granted
#define PATREON_LICENSE_STATUS_MISMATCH 2   // HWID doesn't match
#define PATREON_LICENSE_STATUS_TRANSFER_LIMIT 3  // Transfer limit exceeded

/**
 * Sets the license management policy
 * 
 * @param policy PATREON_LICENSE_POLICY_BLOCK (0) or PATREON_LICENSE_POLICY_TRANSFER (1)
 * @return PATREON_SUCCESS (0) on success
 */
PATREON_AUTH_API int PATREON_SetLicensePolicy(int policy);

/**
 * Checks license status for a token (HWID binding)
 * 
 * @param access_token Patreon OAuth2 access token
 * @return License status code (PATREON_LICENSE_STATUS_*)
 */
PATREON_AUTH_API int PATREON_CheckLicenseStatus(const char* access_token);

/**
 * Registers or transfers license to current device
 * 
 * @param access_token Patreon OAuth2 access token
 * @param force_transfer If 1, forces transfer even if limit exceeded (use with caution)
 * @return PATREON_SUCCESS (0) on success, negative error code otherwise
 */
PATREON_AUTH_API int PATREON_RegisterOrTransferLicense(const char* access_token, int force_transfer);

/**
 * Gets the registered HWID for a token
 * 
 * @param access_token Patreon OAuth2 access token
 * @param hwid_buffer Output buffer for HWID (must be pre-allocated)
 * @param buffer_size Size of hwid_buffer
 * @return Length of HWID copied, 0 if not found or error
 */
PATREON_AUTH_API size_t PATREON_GetRegisteredHWID(const char* access_token, char* hwid_buffer, size_t buffer_size);

/**
 * Verifies member with license check (HWID binding)
 * Combines Patreon verification with license management
 * 
 * @param access_token Patreon OAuth2 access token
 * @param campaign_id Optional campaign ID
 * @param tier_title Optional tier title (NULL for any tier)
 * @param tier_id Optional tier ID (takes precedence over tier_title if both are provided)
 * @param timeout_seconds Network timeout
 * @return PATREON_SUCCESS (0) if member is active and licensed, negative error code otherwise
 */
PATREON_AUTH_API int PATREON_VerifyMemberWithLicense(const char* access_token, const char* campaign_id, const char* tier_title, const char* tier_id, int timeout_seconds);

/**
 * Subscription history information structure
 */
typedef struct {
    int subscription_started_year;      // Year when subscription started (e.g., 2024)
    int subscription_started_month;     // Month when subscription started (1-12)
    int subscription_started_day;       // Day when subscription started (1-31)
    int months_active;                  // Number of months as active patron
    long total_support_cents;           // Total lifetime support in cents
    int is_active;                      // 1 if currently active, 0 otherwise
    char member_since[32];              // Human-readable date string (e.g., "2024-01-15")
} PATREON_SubscriptionHistory;

/**
 * Gets subscription history and tenure information for a Patreon member
 * 
 * @param access_token Patron's/user's OAuth2 access token. This is the token obtained via OAuth2 
 *                     flow that identifies the patron, NOT the creator's/client token.
 * @param history Output structure for subscription history (must be pre-allocated)
 * @param timeout_seconds Network timeout in seconds (default: 10 if 0)
 * @return PATREON_SUCCESS (0) on success, negative error code otherwise
 */
PATREON_AUTH_API int PATREON_GetSubscriptionHistory(const char* access_token, PATREON_SubscriptionHistory* history, int timeout_seconds);

/**
 * Member details structure
 */
typedef struct {
    int is_free_tier;                      // 1 if free tier member, 0 if paid
    int is_free_trial;                     // 1 if in free trial period, 0 otherwise
    int tier_id;                           // Tier ID (0 if free tier)
    long currently_entitled_amount_cents;  // Amount in cents (0 for free tier)
    char subscription_type[32];            // "Free", "Paid", or "Free Trial"
    char tier_description[128];            // Description of tier (if available)
    char created[32];                      // User account creation date (ISO format)
    int is_email_verified;                 // 1 if email is verified, 0 otherwise
    int is_creator;                        // 1 if user is a creator, 0 otherwise
    int can_see_nsfw;                      // 1 if user can see NSFW content, 0 otherwise
    char first_name[64];                   // User's first name
    char last_name[64];                    // User's last name
} PATREON_MemberDetails;

/**
 * Gets member details including tier and subscription type
 * 
 * @param access_token Patron's/user's OAuth2 access token. This is the token obtained via OAuth2 
 *                     flow that identifies the patron, NOT the creator's/client token.
 * @param member_details Output structure for member details (must be pre-allocated)
 * @param timeout_seconds Network timeout in seconds (default: 10 if 0)
 * @return PATREON_SUCCESS (0) on success, negative error code otherwise
 */
PATREON_AUTH_API int PATREON_GetMemberDetails(const char* access_token, PATREON_MemberDetails* member_details, int timeout_seconds);

/**
 * OAuth2 Token Response Structure
 */
typedef struct {
    char access_token[2048];      // Access token
    char refresh_token[2048];     // Refresh token (if provided)
    char token_type[32];          // Token type (usually "Bearer")
    int expires_in;               // Expiration time in seconds (-1 if not provided)
    char scope[512];              // Token scope (if provided)
} PATREON_TokenResponse;

/**
 * Sets the server URL for OAuth2 and API operations
 * When set, library will use this server instead of directly calling Patreon API
 * Set to NULL to use direct Patreon API (default behavior)
 * 
 * @param server_url Base URL of your server (e.g., "https://api.example.com") or NULL
 * @return PATREON_SUCCESS (0) on success, negative error code otherwise
 */
PATREON_AUTH_API int PATREON_SetServerURL(const char* server_url);

/**
 * Gets the currently configured server URL
 * 
 * @param server_url_buffer Output buffer for server URL (must be pre-allocated)
 * @param buffer_size Size of server_url_buffer
 * @return Length of URL copied, 0 if not set
 */
PATREON_AUTH_API size_t PATREON_GetServerURL(char* server_url_buffer, size_t buffer_size);

/**
 * Starts OAuth2 authorization flow by opening browser
 * Opens Patreon authorization URL in default browser
 * 
 * @param client_id Your Patreon application client_id
 * @param redirect_uri Redirect URI registered in your Patreon application (must match exactly)
 * @param scope Optional scope string (e.g., "identity identity.memberships", NULL for default)
 * @return PATREON_SUCCESS (0) on success, negative error code otherwise
 */
PATREON_AUTH_API int PATREON_StartOAuthFlow(const char* client_id, const char* redirect_uri, const char* scope);

/**
 * Exchanges authorization code for access token via your server
 * Your server should handle the OAuth2 code exchange with Patreon API
 * 
 * @param code Authorization code received from Patreon redirect
 * @param redirect_uri Redirect URI used in authorization (must match exactly)
 * @param token_response Output structure for token response (must be pre-allocated)
 * @param timeout_seconds Network timeout in seconds (default: 30 if 0)
 * @return PATREON_SUCCESS (0) on success, negative error code otherwise
 */
PATREON_AUTH_API int PATREON_ExchangeCodeForToken(const char* code, const char* redirect_uri, PATREON_TokenResponse* token_response, int timeout_seconds);

/**
 * Refreshes access token using refresh token via your server
 * Your server should handle the token refresh with Patreon API
 * 
 * @param refresh_token Refresh token from previous authentication
 * @param token_response Output structure for new token response (must be pre-allocated)
 * @param timeout_seconds Network timeout in seconds (default: 30 if 0)
 * @return PATREON_SUCCESS (0) on success, negative error code otherwise
 */
PATREON_AUTH_API int PATREON_RefreshToken(const char* refresh_token, PATREON_TokenResponse* token_response, int timeout_seconds);

#ifdef __cplusplus
}
#endif

#endif // PATREON_AUTH_H

