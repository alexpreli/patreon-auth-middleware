#include "../../include/patreon_auth.h"
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <string>

// Linux implementation of SHA256 calculation using OpenSSL
bool CalculateSHA256_Linux(const void* data, size_t size, uint8_t* hash_out) {
    if (!data || size == 0 || !hash_out) return false;
    
    SHA256_CTX ctx;
    if (SHA256_Init(&ctx)) {
        if (SHA256_Update(&ctx, data, size)) {
            if (SHA256_Final(hash_out, &ctx)) {
                return true;
            }
        }
    }
    return false;
}

// Linux implementation of HMAC-SHA256 using OpenSSL
std::string ComputeHMAC_Linux(const std::string& data, const std::string& secret) {
    std::string signature;
    
    unsigned char* digest = HMAC(EVP_sha256(), 
                                 secret.c_str(), static_cast<int>(secret.length()),
                                 (unsigned char*)data.c_str(), static_cast<int>(data.length()),
                                 nullptr, nullptr);
    
    if (digest) {
        std::stringstream ss;
        for (int i = 0; i < 32; i++) {
            ss << std::hex << std::setfill('0') << std::setw(2) 
               << static_cast<int>(digest[i]);
        }
        signature = ss.str();
    }
    
    return signature;
}

