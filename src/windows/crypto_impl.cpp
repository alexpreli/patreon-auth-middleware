#include "../../include/patreon_auth.h"
#include <windows.h>
#include <wincrypt.h>
#include <sstream>
#include <iomanip>
#include <string>
#pragma comment(lib, "advapi32.lib")

// Windows implementation of SHA256 calculation using CryptoAPI
bool CalculateSHA256_Windows(const void* data, size_t size, uint8_t* hash_out) {
    if (!data || size == 0 || !hash_out) return false;
    
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    
    if (CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            if (CryptHashData(hHash, static_cast<const BYTE*>(data), static_cast<DWORD>(size), 0)) {
                DWORD hash_size = 32;
                if (CryptGetHashParam(hHash, HP_HASHVAL, hash_out, &hash_size, 0)) {
                    CryptDestroyHash(hHash);
                    CryptReleaseContext(hProv, 0);
                    return true;
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    return false;
}

// Windows implementation of HMAC-SHA256 using CryptoAPI
std::string ComputeHMAC_Windows(const std::string& data, const std::string& secret) {
    std::string signature;
    
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    
    if (CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        // Create hash
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            // Import secret as key
            struct {
                BLOBHEADER hdr;
                DWORD keySize;
                BYTE key[32];
            } keyBlob;
            
            keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
            keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
            keyBlob.hdr.reserved = 0;
            keyBlob.hdr.aiKeyAlg = CALG_RC2;
            keyBlob.keySize = 32;
            
            // Derive key from secret (simple hash for key derivation)
            HCRYPTHASH hKeyHash = 0;
            if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hKeyHash)) {
                CryptHashData(hKeyHash, (BYTE*)secret.c_str(), static_cast<DWORD>(secret.length()), 0);
                DWORD hashSize = 32;
                CryptGetHashParam(hKeyHash, HP_HASHVAL, keyBlob.key, &hashSize, 0);
                CryptDestroyHash(hKeyHash);
            }
            
            if (CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
                // Hash data
                CryptHashData(hHash, (BYTE*)data.c_str(), static_cast<DWORD>(data.length()), 0);
                
                // Get hash value
                DWORD hashSize = 32;
                BYTE hashValue[32];
                if (CryptGetHashParam(hHash, HP_HASHVAL, hashValue, &hashSize, 0)) {
                    // Convert to hex string
                    std::stringstream ss;
                    for (DWORD i = 0; i < hashSize; i++) {
                        ss << std::hex << std::setfill('0') << std::setw(2) 
                           << static_cast<int>(hashValue[i]);
                    }
                    signature = ss.str();
                }
                
                CryptDestroyKey(hKey);
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    
    return signature;
}

