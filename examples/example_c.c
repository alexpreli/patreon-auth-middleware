/* Example usage of Patreon Auth Middleware in C */
#include "../include/patreon_auth.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <access_token>\n", argv[0]);
        return 1;
    }
    
    const char* access_token = argv[1];
    
    printf("Verifying Patreon membership...\n");
    
    /* Verify member status with 10 second timeout */
    int result = PATREON_VerifyMember(access_token, NULL, 0, 10);
    
    if (result == PATREON_SUCCESS) {
        printf("SUCCESS: User is an active Patreon member!\n");
    } else {
        char error_msg[512] = {0};
        size_t error_len = PATREON_GetLastError(error_msg, sizeof(error_msg));
        
        if (error_len > 0) {
            fprintf(stderr, "ERROR: %s\n", error_msg);
        } else {
            fprintf(stderr, "ERROR: Verification failed with code %d\n", result);
        }
        
        return 1;
    }
    
    /* Check specific tier access (example tier ID: 12345) */
    printf("\nChecking tier access (Tier ID: 12345)...\n");
    result = PATREON_CheckTierAccess(access_token, 12345, 10);
    
    if (result == PATREON_STATUS_ACTIVE) {
        printf("User has access to tier 12345\n");
    } else if (result == PATREON_STATUS_INACTIVE) {
        printf("User does not have access to tier 12345\n");
    } else {
        char error_msg[512] = {0};
        PATREON_GetLastError(error_msg, sizeof(error_msg));
        fprintf(stderr, "Error checking tier: %s\n", error_msg);
    }
    
    return 0;
}

