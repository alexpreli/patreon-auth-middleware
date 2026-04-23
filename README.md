# Patreon Subscription Verification on User Login

A universal C++ middleware library for verifying Patreon subscription status on user login. This library provides both a DLL/shared library interface and a CLI tool that can be integrated into any programming language or application to verify if users are active Patreon patrons.

> [!IMPORTANT]
> This is the C++ middleware library. For the required backend server, see the **[patreon-auth-middleware-server](https://github.com/alexpreli/patreon-auth-middleware-server)** repository (Patreon Auth Middleware Express.js Server and OAuth2 Callback Native Node.js Server).


## Features

- ✅ **Universal Compatibility**: C-style ABI interface that works with any language (C++, C#, Python, Rust, etc.)
- ✅ **Dual Interface**: Available as both a DLL/shared library and a standalone CLI tool
- ✅ **Robust Error Handling**: Comprehensive error codes and thread-safe error messages
- ✅ **Network Timeouts**: Configurable timeout settings to prevent hanging
- ✅ **Input Validation**: Validates all input parameters before processing
- ✅ **Type Safety**: Proper type conversions and memory management
- ✅ **Cross-Platform**: Supports Windows (WinHTTP) and Linux/Unix (libcurl)

## Common Use Cases

This library is designed for creators who want to monetize their digital products  or provide exclusive content to Patreon supporters.

*   **🎮 Game Launchers & Mods**: Verify a player's membership tier before allowing them to launch "Supporter-Only" builds or load premium game modifications/mods.
*   **💻 Software & Desktop Applications**: Unlock "Premium" or "Pro" features in your software based on the user's active Patreon subscription.
*   **📱 Mobile Applications**: Use the library (via C++ integration) to verify subscription status in high-performance Android or iOS apps.
*   **🌐 Web Applications**: Secure your web app's backend APIs by verifying the patron's access token directly on your server before serving premium data.
*   **🔒 License Management**: Use the built-in **HWID (Hardware ID)** binding to ensure that a single Patreon account isn't being shared across dozens of different computers.
*   **🏅 Loyalty Offers**: Access subscription history to reward long-term patrons with exclusive items, lower prices or "Legacy" badges based on their lifetime support.
*   **🛠️ CLI Tools & Automation**: Integrate Patreon verification into command-line tools for developers, artists, or researchers.


## Building

### Prerequisites

- CMake 3.12 or higher
- C++11 compatible compiler (GCC, Clang, MSVC)
- On Linux/Unix: libcurl development libraries (`sudo apt-get install libcurl4-openssl-dev` or equivalent)

### Build Instructions

```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

### Output Files

- **Library**: `libpatreon_auth.so` (Linux) or `patreon_auth.dll` (Windows)
- **CLI Tool**: `patreon_auth_cli` (Linux) or `patreon_auth_cli.exe` (Windows)
- **Header**: `include/patreon_auth.h`

For detailed building instructions, platform-specific notes, and production configurations, see **[BUILDING.md](BUILDING.md)**.

For a comprehensive guide on production deployment and security best practices, see **[PRODUCTION.md](PRODUCTION.md)**.

## Important: Understanding Access Tokens

**Critical**: This library requires the **patron's/user's OAuth2 access token**, NOT the creator's/client token or client secret.

- **What to use**: The OAuth2 access token obtained when a patron (user) authorizes your application. This token identifies the patron checking their membership status.
- **What NOT to use**: Your creator's/client ID, client secret, or any application-level tokens. These are only used during OAuth2 setup.
- **How to get it**: Use the OAuth2 flow (`--oauth-start`/`--oauth-exchange`) to obtain the patron's token, or implement OAuth2 manually in your application.

The token you provide with `--user-token` or `PATREON_VerifyMember()` must be the token of the **patron** (the person subscribing to a Patreon creator), not your application's credentials.

## Usage

### CLI Tool

The CLI tool can be used directly from the command line or called from other programs:

```bash
# Basic verification (using patron's/user's access token)
patreon_auth_cli --user-token PATRON_ACCESS_TOKEN

# Check specific tier
patreon_auth_cli --user-token PATRON_ACCESS_TOKEN --tier 12345

# Get detailed member information (JSON)
patreon_auth_cli --user-token PATRON_ACCESS_TOKEN --info

# Custom timeout
patreon_auth_cli --user-token PATRON_ACCESS_TOKEN --timeout 15
```


#### Exit Codes

- `0` - Member is active
- `1` - Member is not active or not subscribed
- `2` - Invalid input parameters
- `3` - Network error
- `4` - Invalid or expired token
- `5` - Invalid API response
- `6` - Memory allocation error
- `99` - Unknown error

### DLL/Shared Library

#### C++ Example

```cpp
#include "patreon_auth.h"
#include <iostream>

int main() {
    // Note: This should be the patron's/user's OAuth2 access token, not the creator's token
    const char* patron_token = "PATRON_ACCESS_TOKEN";
    
    int result = PATREON_VerifyMember(patron_token, nullptr, 0, 10);
    
    if (result == PATREON_SUCCESS) {
        std::cout << "User is an active member!" << std::endl;
    } else {
        char error[512];
        PATREON_GetLastError(error, sizeof(error));
        std::cerr << "Error: " << error << std::endl;
    }
    
    return 0;
}
```

#### C# Example

```csharp
using System;
using System.Runtime.InteropServices;

class PatreonAuth {
    [DllImport("patreon_auth.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int PATREON_VerifyMember(
        string access_token, 
        string campaign_id, 
        int tier_id, 
        int timeout_seconds
    );
    
    [DllImport("patreon_auth.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int PATREON_GetLastError(
        System.Text.StringBuilder buffer, 
        int bufferSize
    );
    
    static void Main() {
        // Note: This should be the patron's/user's OAuth2 access token, not the creator's token
        int result = PATREON_VerifyMember("PATRON_ACCESS_TOKEN", null, 0, 10);
        
        if (result == 0) {
            Console.WriteLine("User is an active member!");
        } else {
            var error = new System.Text.StringBuilder(512);
            PATREON_GetLastError(error, error.Capacity);
            Console.WriteLine($"Error: {error}");
        }
    }
}
```

#### Python Example (Using CLI Tool)

```python
import subprocess
import json

# Verify member status using CLI tool
def verify_member(access_token, tier_id=0):
    args = ['patreon_auth_cli', '--user-token', access_token]
    if tier_id > 0:
        args.extend(['--tier', str(tier_id)])
    
    result = subprocess.run(args, capture_output=True, text=True)
    
    if result.returncode == 0:
        return {'success': True, 'message': 'Member is active'}
    else:
        return {'success': False, 'message': 'Member is not active'}

# Usage
result = verify_member("PATRON_ACCESS_TOKEN", tier_id=0)
print(result)
```

**Full example:** See [`examples/example_python.py`](examples/example_python.py) for a complete Python implementation.

#### JavaScript Example (Node.js)

```javascript
const { exec } = require('child_process');
const { promisify } = require('util');

const execPromise = promisify(exec);

// Verify member status using CLI tool
async function verifyMember(accessToken, tierId = 0) {
    const args = ['--user-token', accessToken];
    if (tierId > 0) args.push('--tier', tierId.toString());
    
    try {
        await execPromise(`patreon_auth_cli ${args.join(' ')}`);
        return { success: true, message: 'Member is active' };
    } catch (error) {
        return { success: false, message: 'Member is not active' };
    }
}

// Usage
verifyMember("PATRON_ACCESS_TOKEN").then(result => {
    console.log(result);
});
```

**Full example:** See [`examples/example_javascript.js`](examples/example_javascript.js) for a complete JavaScript implementation.

#### TypeScript Example (Node.js)

```typescript
import { exec } from 'child_process';
import { promisify } from 'util';

const execPromise = promisify(exec);

interface VerifyResult {
    success: boolean;
    message: string;
}

async function verifyMember(accessToken: string, tierId: number = 0): Promise<VerifyResult> {
    const args = ['--user-token', accessToken];
    if (tierId > 0) args.push('--tier', tierId.toString());
    
    try {
        await execPromise(`patreon_auth_cli ${args.join(' ')}`);
        return { success: true, message: 'Member is active' };
    } catch (error) {
        return { success: false, message: 'Member is not active' };
    }
}

// Usage
verifyMember("PATRON_ACCESS_TOKEN").then(result => {
    console.log(result);
});
```

**Full example:** See [`examples/example_typescript.ts`](examples/example_typescript.ts) for a complete TypeScript implementation.

#### Lua Example

```lua
-- Verify member status using CLI tool
function verifyMember(accessToken, tierId)
    tierId = tierId or 0
    local args = {'--user-token', accessToken}
    if tierId > 0 then
        table.insert(args, '--tier')
        table.insert(args, tostring(tierId))
    end
    
    local command = 'patreon_auth_cli ' .. table.concat(args, ' ')
    local handle = io.popen(command)
    local result = handle:read('*a')
    local exitCode = handle:close()
    
    return exitCode == 0
end

-- Usage
local success = verifyMember("PATRON_ACCESS_TOKEN", 0)
print(success and "Member is active" or "Member is not active")
```

**Full example:** See [`examples/example_lua.lua`](examples/example_lua.lua) for a complete Lua implementation.

#### Java Example

```java
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class PatreonAuth {
    private static final String CLI_PATH = "patreon_auth_cli"; // Adjust path as needed
    
    public static class VerifyResult {
        public boolean success;
        public String message;
        
        public VerifyResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
    }
    
    /**
     * Verify Patreon member status using CLI tool
     * @param accessToken Patron's/user's OAuth2 access token (NOT creator's token)
     * @param tierId Optional tier ID (0 for any tier)
     */
    public static VerifyResult verifyMember(String accessToken, int tierId) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(CLI_PATH);
        command.add("--user-token");
        command.add(accessToken);
        
        if (tierId > 0) {
            command.add("--tier");
            command.add(String.valueOf(tierId));
        }
        
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        Process process = processBuilder.start();
        
        // Read output
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }
        
        // Wait for process with timeout
        boolean finished = process.waitFor(30, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            throw new Exception("Request timeout");
        }
        
        int exitCode = process.exitValue();
        
        switch (exitCode) {
            case 0:
                return new VerifyResult(true, "Member is active");
            case 1:
                return new VerifyResult(false, "Member is not active");
            default:
                throw new Exception("Verification failed");
        }
    }
    
    public static void main(String[] args) {
        try {
            // Note: This should be the patron's/user's OAuth2 access token, not the creator's token
            VerifyResult result = verifyMember("PATRON_ACCESS_TOKEN", 0);
            
            if (result.success) {
                System.out.println("User is an active member!");
            } else {
                System.out.println("User is not an active member");
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}
```

**Full example:** See [`examples/example_java.java`](examples/example_java.java) for a complete Java implementation.

### Complete Examples

For complete, runnable examples in multiple languages, see the [`examples/`](examples/) directory:

- **C**: [`examples/example_c.c`](examples/example_c.c) - Direct DLL/shared library usage
- **C++**: [`examples/example_cpp.cpp`](examples/example_cpp.cpp) - Direct DLL/shared library usage
- **Java**: [`examples/example_java.java`](examples/example_java.java) - CLI tool integration
- **JavaScript (Node.js)**: [`examples/example_javascript.js`](examples/example_javascript.js) - CLI tool integration
- **Python**: [`examples/example_python.py`](examples/example_python.py) - CLI tool integration
- **TypeScript**: [`examples/example_typescript.ts`](examples/example_typescript.ts) - CLI tool integration
- **Lua**: [`examples/example_lua.lua`](examples/example_lua.lua) - CLI tool integration
- **License Management**: [`examples/example_license.cpp`](examples/example_license.cpp) - HWID binding example

## API Reference

### OAuth2 Functions

#### `PATREON_SetServerURL`

Sets the server URL for OAuth2 operations. When set, the library will use this server for OAuth2 code exchange and token refresh instead of directly calling Patreon.

**Parameters:**
- `server_url`: Base URL of your server (e.g., "https://api.example.com") or NULL to use direct Patreon API

**Returns:** `PATREON_SUCCESS` (0) on success, negative error code otherwise

#### `PATREON_StartOAuthFlow`

Starts OAuth2 authorization flow by opening the Patreon authorization URL in the default browser.

**Parameters:**
- `client_id`: Your Patreon application client_id
- `redirect_uri`: Redirect URI registered in your Patreon application (must match exactly)
- `scope`: Optional scope string (e.g., "identity identity.memberships", NULL for default)

**Returns:** `PATREON_SUCCESS` (0) on success, negative error code otherwise

#### `PATREON_ExchangeCodeForToken`

Exchanges an authorization code for an access token via your server.

**Parameters:**
- `code`: Authorization code received from Patreon redirect
- `redirect_uri`: Redirect URI used in authorization (must match exactly)
- `token_response`: Output structure for token response (must be pre-allocated)
- `timeout_seconds`: Network timeout in seconds (default: 30 if 0)

**Returns:** `PATREON_SUCCESS` (0) on success, negative error code otherwise

#### `PATREON_RefreshToken`

Refreshes an access token using a refresh token via your server.

**Parameters:**
- `refresh_token`: Refresh token from previous authentication
- `token_response`: Output structure for new token response (must be pre-allocated)
- `timeout_seconds`: Network timeout in seconds (default: 30 if 0)

**Returns:** `PATREON_SUCCESS` (0) on success, negative error code otherwise


### Verification Functions

#### `PATREON_VerifyMember`

Verifies if a user is an active Patreon member.

```c
int PATREON_VerifyMember(
    const char* access_token,  // Patron's/user's OAuth2 access token (NOT creator's token)
    const char* campaign_id,   // Optional, can be NULL
    int tier_id,               // Optional, 0 to check any tier
    int timeout_seconds        // Network timeout, 0 for default (10s)
);
```

**Parameters:**
- `access_token`: **Patron's/user's OAuth2 access token** obtained via OAuth2 flow. This identifies the patron checking their membership status.

**Returns:**
- `PATREON_SUCCESS` (0) - Member is active
- Negative error code on failure

#### `PATREON_GetMemberInfo`

Gets detailed member information in JSON format.

```c
int PATREON_GetMemberInfo(
    const char* access_token,  // Patron's/user's OAuth2 access token
    char* member_info,         // Output buffer (must be pre-allocated)
    size_t buffer_size,        // Size of output buffer
    int timeout_seconds        // Network timeout, 0 for default (10s)
);
```

**Parameters:**
- `access_token`: **Patron's/user's OAuth2 access token** obtained via OAuth2 flow. This identifies the patron whose information you're retrieving.

**Returns:**
- `PATREON_SUCCESS` (0) - Success, member_info contains JSON
- Negative error code on failure

#### `PATREON_CheckTierAccess`

Checks if user has access to a specific tier.

```c
int PATREON_CheckTierAccess(
    const char* access_token,  // Patron's/user's OAuth2 access token
    int tier_id,               // Tier ID to check
    int timeout_seconds        // Network timeout, 0 for default (10s)
);
```

**Parameters:**
- `access_token`: **Patron's/user's OAuth2 access token** obtained via OAuth2 flow. This identifies the patron whose tier access you're checking.

**Returns:**
- `PATREON_STATUS_ACTIVE` (1) - User has access
- `PATREON_STATUS_INACTIVE` (0) - User does not have access
- Negative error code on failure

#### `PATREON_GetLastError`

Gets the last error message (thread-safe).

```c
size_t PATREON_GetLastError(
    char* error_buffer,        // Output buffer (must be pre-allocated)
    size_t buffer_size         // Size of output buffer
);
```

**Returns:** Length of error message string

#### `PATREON_GetHardwareID`

Gets the Hardware ID (HWID) of the current machine.

```c
size_t PATREON_GetHardwareID(
    char* hwid_buffer,         // Output buffer (must be pre-allocated)
    size_t buffer_size         // Size of hwid_buffer
);
```

**Returns:** Length of HWID string, 0 on error

#### `PATREON_SignRequest`

Signs a request with HMAC-SHA256 for server verification.

```c
int PATREON_SignRequest(
    const char* data,          // Data to sign
    const char* secret,        // Secret key for signing
    char* signature_buffer,    // Output buffer (must be at least 65 bytes)
    size_t buffer_size         // Size of signature_buffer
);
```

**Returns:** `PATREON_SUCCESS` (0) on success, negative error code otherwise

#### `PATREON_SetLogCallback`

Sets optional logging callback function.

```c
typedef void (*PATREON_LogCallback)(const char* message, void* user_data);
int PATREON_SetLogCallback(PATREON_LogCallback callback, void* user_data);
```

**Returns:** `PATREON_SUCCESS` (0) on success

#### `PATREON_TokenNeedsRefresh`

Checks if token needs refresh based on expiration.

```c
int PATREON_TokenNeedsRefresh(const char* access_token);
```

**Returns:** 1 if token needs refresh, 0 if still valid, negative on error

#### `PATREON_VerifyClientIntegrity`

Verifies client integrity (anti-patching check).

```c
int PATREON_VerifyClientIntegrity();
```

**Returns:** 1 if client is intact, 0 if patching detected

#### `PATREON_IsClientPatched`

Quick check if client has been patched.

```c
int PATREON_IsClientPatched();
```

**Returns:** 1 if patched, 0 if not patched

#### `PATREON_SetLicensePolicy`

Sets the license management policy (block or transfer).

```c
int PATREON_SetLicensePolicy(int policy);
// policy: PATREON_LICENSE_POLICY_BLOCK (0) or PATREON_LICENSE_POLICY_TRANSFER (1)
```

**Returns:** `PATREON_SUCCESS` (0) on success

#### `PATREON_CheckLicenseStatus`

Checks license status for a token (HWID binding).

```c
int PATREON_CheckLicenseStatus(const char* access_token);
```

**Returns:** License status code:
- `PATREON_LICENSE_STATUS_NEW` (0) - New device, needs registration
- `PATREON_LICENSE_STATUS_VALID` (1) - HWID matches, access granted
- `PATREON_LICENSE_STATUS_MISMATCH` (2) - HWID doesn't match
- `PATREON_LICENSE_STATUS_TRANSFER_LIMIT` (3) - Transfer limit exceeded

#### `PATREON_RegisterOrTransferLicense`

Registers or transfers license to current device.

```c
int PATREON_RegisterOrTransferLicense(
    const char* access_token,
    int force_transfer          // If 1, forces transfer even if limit exceeded
);
```

**Returns:** `PATREON_SUCCESS` (0) on success, negative error code otherwise

#### `PATREON_GetRegisteredHWID`

Gets the registered HWID for a token.

```c
size_t PATREON_GetRegisteredHWID(
    const char* access_token,
    char* hwid_buffer,          // Output buffer (must be pre-allocated)
    size_t buffer_size          // Size of hwid_buffer
);
```

**Returns:** Length of HWID string, 0 if not found or error

#### `PATREON_VerifyMemberWithLicense`

Verifies member with license check (HWID binding). Combines Patreon verification with license management.

```c
int PATREON_VerifyMemberWithLicense(
    const char* access_token,
    const char* campaign_id,    // Optional, can be NULL
    int tier_id,                // Optional, 0 for any tier
    int timeout_seconds         // Network timeout
);
```

**Returns:** `PATREON_SUCCESS` (0) if member is active and licensed, negative error code otherwise

### Error Codes

| Code | Constant | Description |
|------|----------|-------------|
| 0 | `PATREON_SUCCESS` | Operation successful |
| -1 | `PATREON_ERROR_INVALID_TOKEN` | Invalid or expired access token |
| -2 | `PATREON_ERROR_NETWORK` | Network connection error |
| -3 | `PATREON_ERROR_TIMEOUT` | Network timeout |
| -4 | `PATREON_ERROR_INVALID_RESPONSE` | Invalid API response format |
| -5 | `PATREON_ERROR_NOT_MEMBER` | User is not an active member |
| -6 | `PATREON_ERROR_INVALID_INPUT` | Invalid input parameters |
| -7 | `PATREON_ERROR_MEMORY` | Memory allocation error |
| -99 | `PATREON_ERROR_UNKNOWN` | Unknown error |

## Error Handling

The library is designed to be crash-safe. All functions:

1. **Validate input** before processing
2. **Catch exceptions** internally and return error codes
3. **Never throw exceptions** across the C interface boundary
4. **Use timeouts** to prevent indefinite hanging
5. **Provide error messages** via `PATREON_GetLastError()`

### Best Practices

When using the library in your application:

```cpp
// Always check return values
int result = PATREON_VerifyMember(token, nullptr, 0, 10);
if (result != PATREON_SUCCESS) {
    // Handle error gracefully
    char error[512];
    PATREON_GetLastError(error, sizeof(error));
    // Log error, show user message, etc.
}

// Validate inputs before calling
if (!token || strlen(token) == 0) {
    // Handle invalid input
    return;
}

// Use appropriate timeouts
int timeout = 10; // seconds
int result = PATREON_VerifyMember(token, nullptr, 0, timeout);
```

## License Management (Anti-Sharing)

The library includes built-in license management to prevent account sharing between devices using Hardware ID (HWID) binding.

### How It Works

1. **First Login**: When a user logs in for the first time, their HWID is registered with their token
2. **Subsequent Logins**: The library checks if the current HWID matches the registered HWID
3. **Policy Enforcement**: Based on the policy you set, the library either blocks or allows transfers

### Usage Examples

#### Policy: Block (Default)
```cpp
// Set policy to block access if HWID doesn't match
PATREON_SetLicensePolicy(PATREON_LICENSE_POLICY_BLOCK);

// Verify with license check
int result = PATREON_VerifyMemberWithLicense(token, nullptr, 0, 10);

if (result == PATREON_SUCCESS) {
    // Access granted - HWID matches or new registration
} else if (result == PATREON_ERROR_NOT_MEMBER) {
    // Access blocked - HWID mismatch
    // Show message: "This account is already used on another device"
}
```

#### Policy: Transfer (Allow Device Transfer)
```cpp
// Set policy to allow transfer to new device
PATREON_SetLicensePolicy(PATREON_LICENSE_POLICY_TRANSFER);

// Verify with license check
int result = PATREON_VerifyMemberWithLicense(token, nullptr, 0, 10);

if (result == PATREON_SUCCESS) {
    // Access granted - license transferred to new device
} else if (result == PATREON_ERROR_NOT_MEMBER) {
    // Transfer limit exceeded (max 1 transfer per week)
    // Show message: "Transfer limit exceeded. Please wait 7 days."
}
```

#### Manual License Management
```cpp
// Check license status
int status = PATREON_CheckLicenseStatus(token);
switch (status) {
case PATREON_LICENSE_STATUS_NEW:
    // New device - register it
    PATREON_RegisterOrTransferLicense(token, 0);
    break;
    
case PATREON_LICENSE_STATUS_VALID:
    // HWID matches - access granted
    break;
    
case PATREON_LICENSE_STATUS_MISMATCH:
    // Different device - handle based on policy
    if (policy == PATREON_LICENSE_POLICY_TRANSFER) {
        // Ask user if they want to transfer
        if (user_wants_transfer) {
            PATREON_RegisterOrTransferLicense(token, 0);
        }
    }
    break;
}

// Get registered HWID
char hwid[256];
size_t len = PATREON_GetRegisteredHWID(token, hwid, sizeof(hwid));
```

### Transfer Limitations

- **Maximum Transfers**: 1 transfer per week per token
- **Cooldown Period**: 7 days between transfers
- **Force Transfer**: Use `force_transfer = 1` to bypass limits (use with caution)

### Storage

Licenses are stored locally in:
- **Windows**: `%APPDATA%\PatreonAuth\licenses.dat`
- **Linux/Unix**: `~/.patreon_auth/licenses.dat`

Data is encrypted with XOR (basic protection). For production, consider server-side storage.

## Getting Patreon Access Tokens

**Important**: The library requires the **patron's/user's OAuth2 access token**, NOT the creator's/client token. The OAuth2 flow obtains the token that identifies the patron checking their membership status.

Before using this library, you must register a client application on Patreon. **You must select "Client API V2"** when registering your client, as this library uses Patreon's API v2 endpoints.

The library supports two methods for obtaining access tokens:

### Method 1: Automatic OAuth2 Flow (Recommended)

The library can handle the OAuth2 flow automatically using a client-server architecture. This keeps your `client_secret` secure on your backend server. The OAuth2 flow obtains the **patron's/user's access token**.

**Requirements:**
1. Register your application at [Patreon Developers](https://www.patreon.com/portal/registration/register-clients)
   - Click "Create Client"
   - Fill in the required information
   - **Important**: Select **"Client API V2"** (required - this library uses Patreon API v2)
   - Set redirect URI (e.g., `http://localhost:8080/callback`)
   - Click "Create Client"
2. Save your `client_id` and `client_secret` (keep the secret secure!)
3. Set up a backend server that handles OAuth2 code exchange (see [patreon-auth-middleware-server](https://github.com/alexpreli/patreon-auth-middleware-server))

**Usage:**
```cpp
// 1. Set your server URL (where OAuth2 operations are handled)
PATREON_SetServerURL("https://your-server.com");

// 2. Start OAuth2 flow (opens browser automatically)
PATREON_StartOAuthFlow("your_client_id", "http://localhost:8080/callback", NULL);

// 3. After user authorizes, extract code from redirect URI
// Example: http://localhost:8080/callback?code=AUTHORIZATION_CODE

// 4. Exchange code for access token (via your server)
PATREON_TokenResponse token_response;
int result = PATREON_ExchangeCodeForToken(
    "AUTHORIZATION_CODE",
    "http://localhost:8080/callback",
    &token_response,
    30  // timeout in seconds
);

if (result == PATREON_SUCCESS) {
    // token_response.access_token is the patron's/user's access token
    // Use it for verification - this identifies the patron checking their membership
    int verify_result = PATREON_VerifyMember(
        token_response.access_token,  // Patron's/user's token
        NULL,  // campaign_id
        0,     // tier_id (0 = any tier)
        10     // timeout
    );
    
    // Optionally refresh token before expiration
    if (token_response.expires_in > 0) {
        // Refresh when near expiration
        PATREON_RefreshToken(token_response.refresh_token, &token_response, 30);
    }
}
```

**CLI Usage:**
```bash
# Set server URL and start OAuth2 flow (this obtains the patron's/user's token)
patreon_auth_cli --server-url https://your-server.com \
                 --oauth-start CLIENT_ID http://localhost:8080/callback

# After authorization, exchange code for token (returns patron's/user's token)
patreon_auth_cli --server-url https://your-server.com \
                 --oauth-exchange AUTHORIZATION_CODE http://localhost:8080/callback

# Verify with patron's/user's access token
patreon_auth_cli --user-token PATRON_ACCESS_TOKEN
```

**Server Implementation:**
Your server must implement endpoints for OAuth2 operations. See [patreon-auth-middleware-server](https://github.com/alexpreli/patreon-auth-middleware-server) for a complete server implementation guide and example code.

### Method 2: Manual OAuth2 Implementation

If you prefer to implement OAuth2 flow yourself:

1. Register your application at [Patreon Developers](https://www.patreon.com/portal/registration/register-clients)
   - **Important**: Select **"Client API V2"** when registering (required - this library uses Patreon API v2)
   - Save your `client_id` and `client_secret` (keep the secret secure!)
2. Implement OAuth2 flow manually in your application
3. The OAuth2 flow will return the **patron's/user's access token** (the token of the patron who authorized your app)
4. Use the obtained patron's/user's access token with this library for verification

**Important**: The access token you obtain via OAuth2 is the token that identifies the patron, not your application/creator. This is what you use with `--user-token` or `PATREON_VerifyMember()`.

For more information, see the [Patreon API Documentation](https://docs.patreon.com/).

## Web Integration

This library can be integrated into web applications in several ways. Since it's a native C++ library, you'll need a backend server to use it with web applications.

### Architecture Overview

For web applications, the recommended architecture is:

```
Web Browser (JavaScript) 
    ↓ HTTP/HTTPS
Your Web Server (Node.js/Python/PHP/etc.)
    ↓ Uses library
Patreon Auth Middleware (DLL/.so)
    ↓ API calls
Patreon API
```

### Method 1: Server-Side Integration (Recommended)

Create a web server that uses the library and exposes REST API endpoints for your web frontend.

#### Node.js Example (Using CLI Tool)

You can call the CLI tool from Node.js:

```javascript
const { exec } = require('child_process');
const path = require('path');

// Path to the compiled CLI tool
const CLI_PATH = path.join(__dirname, 'patreon_auth_cli.exe'); // Windows
// const CLI_PATH = path.join(__dirname, 'patreon_auth_cli'); // Linux

/**
 * Verify Patreon member status
 * @param {string} accessToken - Patron's/user's OAuth2 access token
 * @param {number} tierId - Optional tier ID (0 for any tier)
 * @returns {Promise<{success: boolean, message: string}>}
 */
async function verifyMember(accessToken, tierId = 0) {
    return new Promise((resolve, reject) => {
        const args = tierId > 0 
            ? [`--user-token`, accessToken, `--tier`, tierId.toString()]
            : [`--user-token`, accessToken];
        
        exec(`"${CLI_PATH}" ${args.join(' ')}`, (error, stdout, stderr) => {
            if (error) {
                // Check exit code
                const exitCode = error.code;
                switch (exitCode) {
                    case 0:
                        resolve({ success: true, message: 'Member is active' });
                        break;
                    case 1:
                        resolve({ success: false, message: 'Member is not active' });
                        break;
                    case 4:
                        reject(new Error('Invalid or expired token'));
                        break;
                    case 3:
                        reject(new Error('Network error'));
                        break;
                    default:
                        reject(new Error(stderr || 'Unknown error'));
                }
            } else {
                resolve({ success: true, message: 'Member is active', data: stdout });
            }
        });
    });
}

/**
 * Get member information as JSON
 * @param {string} accessToken - Patron's/user's Patreon OAuth2 access token
 * @returns {Promise<Object>}
 */
async function getMemberInfo(accessToken) {
    return new Promise((resolve, reject) => {
        exec(`"${CLI_PATH}" --user-token "${accessToken}" --info`, (error, stdout, stderr) => {
            if (error) {
                reject(new Error(stderr || 'Failed to get member info'));
            } else {
                try {
                    const info = JSON.parse(stdout);
                    resolve(info);
                } catch (e) {
                    reject(new Error('Invalid JSON response'));
                }
            }
        });
    });
}

// Express.js endpoint example
const express = require('express');
const app = express();

app.use(express.json());

app.post('/api/verify', async (req, res) => {
    try {
        const { token, tier_id } = req.body;  // token is patron's/user's OAuth2 access token
        
        if (!token) {
            return res.status(400).json({ error: 'Patron access token required' });
        }
        
        const result = await verifyMember(token, tier_id || 0);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/member-info', async (req, res) => {
    try {
        const { token } = req.body;
        
        if (!token) {
            return res.status(400).json({ error: 'Token required' });
        }
        
        const info = await getMemberInfo(token);
        res.json(info);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
```

#### Python Flask Example (Using CLI Tool)

```python
from flask import Flask, request, jsonify
import subprocess
import json
import os

app = Flask(__name__)

# Path to CLI tool
CLI_PATH = os.path.join(os.path.dirname(__file__), 'patreon_auth_cli')
# Windows: CLI_PATH = os.path.join(os.path.dirname(__file__), 'patreon_auth_cli.exe')

def verify_member(access_token, tier_id=0):
    """Verify Patreon member status using CLI tool
    Args:
        access_token: Patron's/user's OAuth2 access token
        tier_id: Optional tier ID to check
    """
    try:
        args = [CLI_PATH, '--user-token', access_token]
        if tier_id > 0:
            args.extend(['--tier', str(tier_id)])
        
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            return {'success': True, 'message': 'Member is active', 'data': result.stdout}
        elif result.returncode == 1:
            return {'success': False, 'message': 'Member is not active'}
        elif result.returncode == 4:
            raise Exception('Invalid or expired token')
        else:
            raise Exception(result.stderr or 'Unknown error')
    except subprocess.TimeoutExpired:
        raise Exception('Request timeout')
    except Exception as e:
        raise Exception(f'Verification failed: {str(e)}')

def get_member_info(access_token):
    """Get member information as JSON
    Args:
        access_token: Patron's/user's OAuth2 access token
    """
    try:
        result = subprocess.run(
            [CLI_PATH, '--user-token', access_token, '--info'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            raise Exception(result.stderr or 'Failed to get member info')
    except json.JSONDecodeError:
        raise Exception('Invalid JSON response')
    except subprocess.TimeoutExpired:
        raise Exception('Request timeout')
    except Exception as e:
        raise Exception(f'Failed to get member info: {str(e)}')

@app.route('/api/verify', methods=['POST'])
def verify():
    try:
        data = request.get_json()
        token = data.get('token')  # Patron's/user's OAuth2 access token
        tier_id = data.get('tier_id', 0)
        
        if not token:
            return jsonify({'error': 'Patron access token required'}), 400
        
        result = verify_member(token, tier_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/member-info', methods=['POST'])
def member_info():
    try:
        data = request.get_json()
        token = data.get('token')
        
        if not token:
            return jsonify({'error': 'Token required'}), 400
        
        info = get_member_info(token)
        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=True)
```

#### PHP Example (Using CLI Tool)

```php
<?php

class PatreonAuthAPI {
    private $cliPath;
    
    public function __construct($cliPath) {
        $this->cliPath = $cliPath;
    }
    
    /**
     * Verify Patreon member status
     * @param string $accessToken Patron's/user's OAuth2 access token
     * @param int $tierId Optional tier ID to check
     */
    public function verifyMember($accessToken, $tierId = 0) {
        $args = [$this->cliPath, '--user-token', escapeshellarg($accessToken)];
        
        if ($tierId > 0) {
            $args[] = '--tier';
            $args[] = escapeshellarg($tierId);
        }
        
        $command = implode(' ', $args);
        $output = [];
        $returnCode = 0;
        
        exec($command . ' 2>&1', $output, $returnCode);
        
        switch ($returnCode) {
            case 0:
                return ['success' => true, 'message' => 'Member is active', 'data' => implode("\n", $output)];
            case 1:
                return ['success' => false, 'message' => 'Member is not active'];
            case 4:
                throw new Exception('Invalid or expired token');
            case 3:
                throw new Exception('Network error');
            default:
                throw new Exception('Unknown error: ' . implode("\n", $output));
        }
    }
    
    /**
     * Get member information as JSON
     * @param string $accessToken Patron's/user's OAuth2 access token
     */
    public function getMemberInfo($accessToken) {
        $command = escapeshellcmd($this->cliPath) . ' --user-token ' . escapeshellarg($accessToken) . ' --info 2>&1';
        $output = [];
        $returnCode = 0;
        
        exec($command, $output, $returnCode);
        
        if ($returnCode == 0) {
            $json = json_decode(implode("\n", $output), true);
            if (json_last_error() === JSON_ERROR_NONE) {
                return $json;
            }
            throw new Exception('Invalid JSON response');
        } else {
            throw new Exception('Failed to get member info: ' . implode("\n", $output));
        }
    }
}

// Usage with Slim Framework or plain PHP
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $token = $input['token'] ?? null;
    
    if (!$token) {
        http_response_code(400);
        echo json_encode(['error' => 'Token required']);
        exit;
    }
    
    $auth = new PatreonAuthAPI(__DIR__ . '/patreon_auth_cli.exe');
    
    try {
        if (strpos($_SERVER['REQUEST_URI'], '/api/member-info') !== false) {
            $info = $auth->getMemberInfo($token);
            echo json_encode($info);
        } else {
            $tierId = $input['tier_id'] ?? 0;
            $result = $auth->verifyMember($token, $tierId);
            echo json_encode($result);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
}
?>
```

### Method 2: Client-Side JavaScript (Browser)

For web applications, you typically make API calls to your backend server which uses the library:

#### JavaScript/TypeScript Example (Browser)

```javascript
/**
 * Patreon Auth API Client for Web Applications
 */
class PatreonAuthClient {
    constructor(apiBaseUrl) {
        this.apiBaseUrl = apiBaseUrl;
    }
    
    /**
     * Verify Patreon member status
     * @param {string} accessToken - Patreon access token
     * @param {number} tierId - Optional tier ID (0 for any tier)
     * @returns {Promise<{success: boolean, message: string}>}
     */
    async verifyMember(accessToken, tierId = 0) {
        try {
            const response = await fetch(`${this.apiBaseUrl}/api/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    token: accessToken,
                    tier_id: tierId
                })
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Verification failed');
            }
            
            return await response.json();
        } catch (error) {
            console.error('Verification error:', error);
            throw error;
        }
    }
    
    /**
     * Get member information
     * @param {string} accessToken - Patreon access token
     * @returns {Promise<Object>}
     */
    async getMemberInfo(accessToken) {
        try {
            const response = await fetch(`${this.apiBaseUrl}/api/member-info`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    token: accessToken
                })
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to get member info');
            }
            
            return await response.json();
        } catch (error) {
            console.error('Get member info error:', error);
            throw error;
        }
    }
    
    /**
     * Check if user has access to specific tier
     * @param {string} accessToken - Patreon access token
     * @param {number} tierId - Tier ID to check
     * @returns {Promise<boolean>}
     */
    async hasTierAccess(accessToken, tierId) {
        const result = await this.verifyMember(accessToken, tierId);
        return result.success;
    }
}

// Usage example
const patreonAuth = new PatreonAuthClient('https://your-api.com');

// Check if user is a Patreon member
async function checkPatreonStatus() {
    const token = localStorage.getItem('patreon_token'); // Get from your auth system
    
    if (!token) {
        console.log('No Patreon token found');
        return;
    }
    
    try {
        // Verify member status
        const verifyResult = await patreonAuth.verifyMember(token);
        
        if (verifyResult.success) {
            console.log('User is an active Patreon member!');
            showPremiumFeatures();
        } else {
            console.log('User is not a Patreon member');
            hidePremiumFeatures();
        }
        
        // Get detailed member info
        const memberInfo = await patreonAuth.getMemberInfo(token);
        console.log('Member info:', memberInfo);
        
        // Check specific tier access
        const hasTierAccess = await patreonAuth.hasTierAccess(token, 12345);
        if (hasTierAccess) {
            console.log('User has access to tier 12345');
        }
        
    } catch (error) {
        console.error('Error checking Patreon status:', error);
    }
}
```

#### React Component Example

```javascript
import React, { useState, useEffect } from 'react';

/**
 * Component to display Patreon membership status
 */
function PatreonStatus({ token }) {
    const [isMember, setIsMember] = useState(false);
    const [loading, setLoading] = useState(true);
    const [memberInfo, setMemberInfo] = useState(null);
    
    useEffect(() => {
        async function checkStatus() {
            if (!token) {
                setLoading(false);
                return;
            }
            
            try {
                // Initialize the client with your backend API URL
                const patreonAuth = new PatreonAuthClient(process.env.REACT_APP_API_URL);
                
                // Verify member status
                const result = await patreonAuth.verifyMember(token);
                setIsMember(result.success);
                
                if (result.success) {
                    // Fetch detailed member info if they are a member
                    const info = await patreonAuth.getMemberInfo(token);
                    setMemberInfo(info);
                }
            } catch (error) {
                console.error('Failed to check Patreon status:', error);
            } finally {
                setLoading(false);
            }
        }
        
        checkStatus();
    }, [token]);
    
    if (loading) {
        return <div className="patreon-loading">Checking Patreon status...</div>;
    }
    
    return (
        <div className="patreon-status-container">
            {isMember ? (
                <div className="patreon-member-active">
                    <h2>Welcome, Patreon Member!</h2>
                    {memberInfo && (
                        <div className="member-details">
                            <p><strong>Member since:</strong> {memberInfo.member_since}</p>
                            <p><strong>Total support:</strong> ${memberInfo.total_support_cents / 100}</p>
                        </div>
                    )}
                </div>
            ) : (
                <div className="patreon-member-inactive">
                    <p>Please become a Patreon member to access premium features.</p>
                </div>
            )}
        </div>
    );
}

export default PatreonStatus;
```

#### OAuth2 Flow in Web Application

If you want to implement OAuth2 flow in your web application:

```javascript
/**
 * Handle OAuth2 callback from Patreon
 */
function handleOAuthCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const error = urlParams.get('error');
    
    if (error) {
        console.error('OAuth error:', error);
        return;
    }
    
    if (code) {
        // Exchange code for token via your server
        exchangeCodeForToken(code);
    }
}

async function exchangeCodeForToken(code) {
    try {
        const response = await fetch('https://your-api.com/oauth/exchange', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                code: code,
                redirect_uri: window.location.origin + '/callback'
            })
        });
        
        if (!response.ok) {
            throw new Error('Token exchange failed');
        }
        
        const tokenData = await response.json();
        
        // Store token securely (consider using httpOnly cookies instead)
        localStorage.setItem('patreon_access_token', tokenData.access_token);
        localStorage.setItem('patreon_refresh_token', tokenData.refresh_token);
        
        // Redirect to main app
        window.location.href = '/dashboard';
    } catch (error) {
        console.error('Failed to exchange code:', error);
    }
}

/**
 * Start OAuth2 flow
 */
function startPatreonOAuth() {
    const clientId = 'your_client_id';
    const redirectUri = encodeURIComponent(window.location.origin + '/callback');
    const scope = 'identity identity.memberships';
    
    const authUrl = `https://www.patreon.com/oauth2/authorize?` +
        `response_type=code&` +
        `client_id=${clientId}&` +
        `redirect_uri=${redirectUri}&` +
        `scope=${scope}`;
    
    window.location.href = authUrl;
}

// Button click handler
document.getElementById('connect-patreon').addEventListener('click', startPatreonOAuth);
```

### Method 3: Using WebAssembly (Future)

For direct browser integration without a backend server, you could compile the library to WebAssembly. However, this requires additional setup and is not currently supported out of the box.

### Security Considerations for Web Integration

1. **Never expose tokens in client-side code**: Always handle OAuth2 flow through your backend server
2. **Use HTTPS**: All API calls should use HTTPS to protect tokens in transit
3. **Token storage**: Consider using httpOnly cookies instead of localStorage for better security
4. **CORS**: Configure CORS properly on your backend server
5. **Rate limiting**: Implement rate limiting on your API endpoints
6. **Token validation**: Always validate tokens on the server side before processing

### Example: Complete Web Application Setup

Here's a complete example structure for a web application:

```
your-web-app/
├── frontend/
│   ├── index.html
│   ├── js/
│   │   └── patreon-client.js (uses PatreonAuthClient class above)
│   └── css/
├── backend/
│   ├── server.js (Node.js with Express)
│   ├── patreon_auth_cli.exe (or .so on Linux)
│   └── routes/
│       └── patreon.js
└── package.json
```

**Backend (server.js):**
```javascript
const express = require('express');
const path = require('path');
const { verifyMember, getMemberInfo } = require('./routes/patreon');

const app = express();
app.use(express.json());
app.use(express.static('frontend'));

// API routes
app.post('/api/verify', verifyMember);
app.post('/api/member-info', getMemberInfo);

app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
```

This setup allows your web frontend to securely communicate with the Patreon Auth Middleware through your backend server.

## ⚠️ Security Warnings and Limitations


**Recommendation**: 
- **ALWAYS implement server-side validation** for critical features
- Never rely solely on client-side verification for premium features or paid content
- Consider implementing a server-side API that performs the actual Patreon verification


#### **Token Security**

- Tokens can be intercepted if the system is compromised
- Tokens can be shared between users

**Recommendation**:
- Store tokens securely (encrypted, not in plain text)
- Implement token rotation/refresh mechanisms
- Consider using Hardware ID (HWID) binding for additional security (requires server-side support)

### Security Features Implemented

This library includes the following security measures to mitigate common attacks:

- ✅ **Rate Limiting**: Prevents DoS attacks (1 request per second per token)
- ✅ **Hostname Validation**: Verifies responses come from official Patreon domains
- ✅ **Response Validation**: Checks for valid Patreon API response structure
- ✅ **SSL/TLS Verification**: Validates SSL certificates (cannot be disabled)
- ✅ **Input Validation**: Validates all inputs to prevent buffer overflows
- ✅ **Safe String Operations**: Uses secure string copying functions
- ✅ **Exception Handling**: Prevents crashes from propagating to host application

### Best Practices for Secure Implementation

1. **Server-Side Validation** (REQUIRED for production):
   ```cpp
   // ❌ BAD: Only client-side check
   if (PATREON_VerifyMember(token, nullptr, 0, 10) == PATREON_SUCCESS) {
       unlockPremiumFeatures(); // Vulnerable to bypass!
   }
   
   // ✅ GOOD: Client-side + Server-side
   if (PATREON_VerifyMember(token, nullptr, 0, 10) == PATREON_SUCCESS) {
       // Show UI as "premium" for better UX
       showPremiumUI();
       
       // But actual access control happens on server
       serverRequest = makeServerRequest(token);
       if (serverRequest.verified) {
           unlockPremiumFeatures(); // Server validates, not client
       }
   }
   ```

2. **Token Management**:
   - Never hardcode tokens in source code
   - Store tokens in encrypted storage
   - Use environment variables for development
   - Implement token refresh mechanisms
   - Log token usage for audit purposes

3. **Error Handling**:
   - Don't expose detailed error messages to end users
   - Log security-related errors server-side
   - Implement fallback mechanisms for network failures

4. **Network Security**:
   - Always use HTTPS (enforced by library)
   - Verify SSL certificates (enforced by library)
   - Monitor for unusual API request patterns


## Platform-Specific Notes

### Windows

- Uses WinHTTP API (no external dependencies)
- DLL exports use `__declspec(dllexport)`
- Compatible with Windows 7 and later

### Linux/Unix

- Requires libcurl (usually pre-installed or available via package manager)
- Shared library uses standard ELF format
- Compatible with most modern distributions

## License

This project is licensed under the [MIT License](LICENSE).

Please ensure compliance with Patreon's Terms of Service and API usage guidelines.

## Contributing

Contributions are welcome! Please ensure:

- Code follows C++11 standards
- Error handling is comprehensive
- Input validation is thorough
- Cross-platform compatibility is maintained

## Troubleshooting

### "Failed to initialize WinHTTP session" (Windows)

- Ensure you're running on Windows 7 or later
- Check Windows Update for latest system files

### "Failed to initialize libcurl" (Linux)

- Install libcurl development package: `sudo apt-get install libcurl4-openssl-dev`
- Verify libcurl is in your library path

### Network Timeouts

- Increase timeout value if you have slow internet
- Check firewall settings
- Verify Patreon API is accessible from your network

### Invalid Token Errors

- Verify token is not expired
- Check token has required scopes (identity, memberships)
- Ensure token format is correct

## Testing

```bash
# Basic verification test
patreon_auth_cli --token YOUR_TOKEN

# Get member info
patreon_auth_cli --token YOUR_TOKEN --info

# Get subscription history
patreon_auth_cli --token YOUR_TOKEN --history

# Test with tier check
patreon_auth_cli --token YOUR_TOKEN --tier TIER_ID
```

## Support

For issues, questions, or contributions, please open an issue on the project repository.

