#ifndef OBFUSCATION_H
#define OBFUSCATION_H

#include <string>
#include <cstring>

// Platform-specific implementations
#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#include "windows/obfuscation_impl.h"
#else
#include <sys/ptrace.h>
#include <unistd.h>
#include <time.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "linux/obfuscation_impl.h"
#endif

// String obfuscation - XOR encryption
namespace Obfuscation {
    // XOR key for string obfuscation (can be changed)
    static const unsigned char XOR_KEY = 0x5A;
    
    // Deobfuscate string at runtime
    inline std::string Deobfuscate(const unsigned char* data, size_t len) {
        std::string result;
        result.reserve(len);
        for (size_t i = 0; i < len; i++) {
            result += static_cast<char>(data[i] ^ XOR_KEY);
        }
        return result;
    }
    
    // Helper to obfuscate a string (for compile-time generation)
    template<size_t N>
    constexpr void ObfuscateString(const char(&input)[N], unsigned char(&output)[N-1]) {
        for (size_t i = 0; i < N - 1; i++) {
            output[i] = static_cast<unsigned char>(input[i]) ^ XOR_KEY;
        }
    }
    
    // Obfuscated Patreon API base URL: "https://www.patreon.com/api/oauth2/v2/identity"
    // XOR-encrypted with key 0x5A
    static const unsigned char OBF_BASE_URL[] = {
        0x32, 0x2E, 0x2E, 0x2A, 0x29, 0x60, 0x75, 0x75, 0x2D, 0x2D, 0x2D, 0x74, 0x2A, 0x3B, 0x2E, 0x28,
        0x3F, 0x35, 0x34, 0x74, 0x39, 0x35, 0x37, 0x75, 0x3B, 0x2A, 0x33, 0x75, 0x35, 0x3B, 0x2F, 0x2E,
        0x32, 0x68, 0x75, 0x2C, 0x68, 0x75, 0x33, 0x3E, 0x3F, 0x34, 0x2E, 0x33, 0x2E, 0x23
    };
    
    // Get deobfuscated base URL
    inline std::string GetBaseURL() {
        return Deobfuscate(OBF_BASE_URL, sizeof(OBF_BASE_URL));
    }
    
    // Anti-debugging functions - forward declarations
#ifdef _WIN32
    bool IsDebuggerPresent_Windows();
    bool VerifyIntegrity_Windows();
#else
    bool IsDebuggerPresent_Linux();
    bool VerifyIntegrity_Linux();
#endif
    
    inline bool IsDebuggerPresent() {
#ifdef _WIN32
        return IsDebuggerPresent_Windows();
#else
        return IsDebuggerPresent_Linux();
#endif
    }
    
    // Anti-tampering: Simple integrity check
    inline bool VerifyIntegrity() {
#ifdef _WIN32
        return VerifyIntegrity_Windows();
#else
        return VerifyIntegrity_Linux();
#endif
    }
    
    // Control flow obfuscation: fake function calls (dead code)
    inline void DeadCode1() {
        volatile int x = 0x12345678;
        volatile int y = 0x87654321;
        volatile int z = x ^ y;
        (void)z;
    }
    
    inline void DeadCode2() {
        volatile int a = 0xABCDEF00;
        volatile int b = 0x00FEDCBA;
        volatile int c = a & b;
        (void)c;
    }
    
    inline void DeadCode3() {
        volatile long long d = 0x123456789ABCDEF0LL;
        volatile long long e = 0xF0EDCBA987654321LL;
        volatile long long f = d | e;
        (void)f;
    }
}

#endif // OBFUSCATION_H
