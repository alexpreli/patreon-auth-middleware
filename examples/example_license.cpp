// Example: License Management with HWID Binding
#include "../include/patreon_auth.h"
#include <iostream>
#include <cstring>

void LogCallback(const char* message, void* user_data) {
    std::endl;
    std::cout << "[LOG] " << message << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <access_token> [policy]" << std::endl;
        std::cerr << "  policy: 'block' (default) or 'transfer'" << std::endl;
        return 1;
    }
    
    const char* token = argv[1];
    const char* policy_str = (argc > 2) ? argv[2] : "block";
    
    std::endl;

    // Set logging 
    PATREON_SetLogCallback(LogCallback, nullptr);
    
    // Set license policy
    int policy = (strcmp(policy_str, "transfer") == 0) ? 
                 PATREON_LICENSE_POLICY_TRANSFER : PATREON_LICENSE_POLICY_BLOCK;
    PATREON_SetLicensePolicy(policy);
    
    std::cout << "License Policy: " << (policy == PATREON_LICENSE_POLICY_BLOCK ? "BLOCK" : "TRANSFER") << std::endl;
    
    // Get current HWID
    char current_hwid[256] = {0};
    size_t hwid_len = PATREON_GetHardwareID(current_hwid, sizeof(current_hwid));
    std::cout << "Current HWID: " << current_hwid << std::endl;
    
    // Check license status
    int license_status = PATREON_CheckLicenseStatus(token);
    std::cout << "\nLicense Status: ";
    switch (license_status) {
    case PATREON_LICENSE_STATUS_NEW:
        std::cout << "NEW DEVICE (needs registration)" << std::endl;
        break;
    case PATREON_LICENSE_STATUS_VALID:
        std::cout << "VALID (HWID matches)" << std::endl;
        break;
    case PATREON_LICENSE_STATUS_MISMATCH:
        std::cout << "MISMATCH (different HWID)" << std::endl;
        break;
    default:
        std::cout << "ERROR" << std::endl;
        return 1;
    }
    
    // Get registered HWID if exists
    char registered_hwid[256] = {0};
    size_t reg_hwid_len = PATREON_GetRegisteredHWID(token, registered_hwid, sizeof(registered_hwid));
    if (reg_hwid_len > 0) {
        std::cout << "Registered HWID: " << registered_hwid << std::endl;
    } else {
        std::cout << "No registered HWID (new license)" << std::endl;
    }
    
    // Verify with license check
    std::cout << "\nVerifying with license check..." << std::endl;
    int result = PATREON_VerifyMemberWithLicense(token, nullptr, 0, 10);
    
    if (result == PATREON_SUCCESS) {
        std::cout << "SUCCESS: Member verified and licensed!" << std::endl;
        
        // Check final status
        license_status = PATREON_CheckLicenseStatus(token);
        if (license_status == PATREON_LICENSE_STATUS_VALID) {
            std::cout << "License is now registered on this device." << std::endl;
        }
    } else {
        char error[512] = {0};
        PATREON_GetLastError(error, sizeof(error));
        std::cerr << "ERROR: " << error << std::endl;
        
        if (result == PATREON_ERROR_NOT_MEMBER) {
            if (license_status == PATREON_LICENSE_STATUS_MISMATCH) {
                if (policy == PATREON_LICENSE_POLICY_BLOCK) {
                    std::cerr << "\nAccess BLOCKED: License is registered on a different device." << std::endl;
                    std::cerr << "To allow transfer, set policy to TRANSFER." << std::endl;
                } else {
                    std::cerr << "\nTransfer may have failed due to rate limiting." << std::endl;
                    std::cerr << "Max 1 transfer per week allowed." << std::endl;
                }
            }
        }
    }
    
    return (result == PATREON_SUCCESS) ? 0 : 1;
}

