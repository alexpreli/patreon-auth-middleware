// Example usage of Patreon Auth Middleware in C++
#include "../include/patreon_auth.h"
#include <iostream>
#include <cstring>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <access_token>" << std::endl;
        return 1;
    }
    
    const char* access_token = argv[1];
    
    std::cout << "Verifying Patreon membership..." << std::endl;
    
    // Verify member status with 10 second timeout
    int result = PATREON_VerifyMember(access_token, nullptr, 0, 10);
    
    if (result == PATREON_SUCCESS) {
        std::cout << "SUCCESS: User is an active Patreon member!" << std::endl;
    } else {
        char error_msg[512] = {0};
        size_t error_len = PATREON_GetLastError(error_msg, sizeof(error_msg));
        
        if (error_len > 0) {
            std::cerr << "ERROR: " << error_msg << std::endl;
        } else {
            std::cerr << "ERROR: Verification failed with code " << result << std::endl;
        }
        
        return 1;
    }
    
    // Get detailed member information
    std::cout << "\nFetching detailed member information..." << std::endl;
    char member_info[8192] = {0};
    result = PATREON_GetMemberInfo(access_token, member_info, sizeof(member_info), 10);
    
    if (result == PATREON_SUCCESS) {
        std::cout << "Member Info (JSON):" << std::endl;
        std::cout << member_info << std::endl;
    } else {
        char error_msg[512] = {0};
        PATREON_GetLastError(error_msg, sizeof(error_msg));
        std::cerr << "Failed to get member info: " << error_msg << std::endl;
    }
    
    return 0;
}

