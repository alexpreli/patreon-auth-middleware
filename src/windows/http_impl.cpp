#include "../../include/patreon_auth.h"
#include "../http_response.h"
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#pragma comment(lib, "winhttp.lib")

// Forward declarations - these are defined in patreon_client.cpp
void SetError(const std::string& error);
bool ValidateHostname(const std::string& hostname);
bool ValidatePatreonResponse(const std::string& response_data);

// Forward declaration for logging
namespace SecurityUtils {
    void LogMessage(const std::string& message);
}

// Connection pooling: Reuse WinHTTP session to avoid TLS handshake on every request
static HINTERNET g_hPatreonSession = nullptr;
static HINTERNET g_hServerSession = nullptr;
static std::mutex g_patreonSessionMutex;
static std::mutex g_serverSessionMutex;
static std::chrono::steady_clock::time_point g_patreonSessionLastUsed;
static std::chrono::steady_clock::time_point g_serverSessionLastUsed;
static const int SESSION_IDLE_TIMEOUT_SECONDS = 300; // Close session after 5 minutes of inactivity

// Helper function to get or create Patreon API session
static HINTERNET GetPatreonSession() {
    std::lock_guard<std::mutex> lock(g_patreonSessionMutex);
    
    auto now = std::chrono::steady_clock::now();
    
    // Check if session exists and is still valid
    if (g_hPatreonSession) {
        auto idle_time = std::chrono::duration_cast<std::chrono::seconds>(
            now - g_patreonSessionLastUsed).count();
        
        // If session is too old, close it and create a new one
        if (idle_time > SESSION_IDLE_TIMEOUT_SECONDS) {
            WinHttpCloseHandle(g_hPatreonSession);
            g_hPatreonSession = nullptr;
        }
    }
    
    // Create new session if needed
    if (!g_hPatreonSession) {
        g_hPatreonSession = WinHttpOpen(L"PatreonAuth/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
                                       WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (g_hPatreonSession) {
            // Set timeouts for the session
            WinHttpSetTimeouts(g_hPatreonSession, 
                15000, // resolve timeout (15s) - increased for first connection
                15000, // connect timeout (15s) - increased for first connection
                30000, // send timeout (30s)
                30000  // receive timeout (30s)
            );
        }
    }
    
    if (g_hPatreonSession) {
        g_patreonSessionLastUsed = now;
    }
    
    return g_hPatreonSession;
}

// Helper function to get or create server session (for OAuth2 operations)
static HINTERNET GetServerSession() {
    std::lock_guard<std::mutex> lock(g_serverSessionMutex);
    
    auto now = std::chrono::steady_clock::now();
    
    // Check if session exists and is still valid
    if (g_hServerSession) {
        auto idle_time = std::chrono::duration_cast<std::chrono::seconds>(
            now - g_serverSessionLastUsed).count();
        
        // If session is too old, close it and create a new one
        if (idle_time > SESSION_IDLE_TIMEOUT_SECONDS) {
            WinHttpCloseHandle(g_hServerSession);
            g_hServerSession = nullptr;
        }
    }
    
    // Create new session if needed
    if (!g_hServerSession) {
        g_hServerSession = WinHttpOpen(L"PatreonAuth/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (g_hServerSession) {
            // Set timeouts for the session
            WinHttpSetTimeouts(g_hServerSession, 
                15000, // resolve timeout (15s) - increased for first connection
                15000, // connect timeout (15s) - increased for first connection
                30000, // send timeout (30s)
                30000  // receive timeout (30s)
            );
        }
    }
    
    if (g_hServerSession) {
        g_serverSessionLastUsed = now;
    }
    
    return g_hServerSession;
}

// Helper function to get WinHTTP error message
std::string GetWinHttpErrorMessage(DWORD error_code) {
    switch (error_code) {
        case ERROR_WINHTTP_TIMEOUT: return "Timeout";
        case ERROR_WINHTTP_NAME_NOT_RESOLVED: return "Name not resolved (DNS error)";
        case ERROR_WINHTTP_CANNOT_CONNECT: return "Cannot connect";
        case ERROR_WINHTTP_CONNECTION_ERROR: return "Connection error";
        case ERROR_WINHTTP_SECURE_FAILURE: return "SSL/TLS failure";
        case ERROR_WINHTTP_INVALID_URL: return "Invalid URL";
        default: return "Error code: " + std::to_string(error_code);
    }
}

// Windows implementation of HTTP request using WinHTTP
HttpResponse MakePatreonRequest_Windows(const std::string& url, const std::string& access_token, int timeout_seconds) {
    HttpResponse response;
    response.success = false;
    response.status_code = 0;
    
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hRequest = nullptr;
    
    try {
        // Reuse pooled session instead of creating new one
        hSession = GetPatreonSession();
        if (!hSession) {
            SetError("Failed to get WinHTTP session");
            return response;
        }
        
        // Parse URL
        std::wstring wurl(url.begin(), url.end());
        URL_COMPONENTSW urlComp;
        ZeroMemory(&urlComp, sizeof(urlComp));
        urlComp.dwStructSize = sizeof(urlComp);
        urlComp.dwSchemeLength = -1;
        urlComp.dwHostNameLength = -1;
        urlComp.dwUrlPathLength = -1;
        
        if (!WinHttpCrackUrl(wurl.c_str(), static_cast<DWORD>(wurl.length()), 0, &urlComp)) {
            // Don't close session - it's pooled
            SetError("Failed to parse URL");
            return response;
        }
        
        std::wstring hostname(urlComp.lpszHostName, urlComp.dwHostNameLength);
        std::wstring path(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
        
        // Validate hostname to prevent MITM attacks
        // Convert wstring to string using WideCharToMultiByte for proper UTF-8 conversion
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, hostname.c_str(), static_cast<int>(hostname.length()), nullptr, 0, nullptr, nullptr);
        std::string hostname_ascii(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, hostname.c_str(), static_cast<int>(hostname.length()), &hostname_ascii[0], size_needed, nullptr, nullptr);
        if (!ValidateHostname(hostname_ascii)) {
            SetError("Invalid hostname - possible MITM attack");
            return response;
        }
        
        hConnect = WinHttpConnect(hSession, hostname.c_str(), urlComp.nPort, 0);
        if (!hConnect) {
            DWORD error = GetLastError();
            std::string error_msg = "Failed to connect to Patreon API: " + GetWinHttpErrorMessage(error);
            SecurityUtils::LogMessage("WinHttpConnect failed: " + error_msg);
            SetError(error_msg);
            // Don't close session - it's pooled and might be reused
            return response;
        }
        
        DWORD flags = WINHTTP_FLAG_SECURE;
        hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(), nullptr, 
                                     WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            // Don't close session - it's pooled
            SetError("Failed to create HTTP request");
            return response;
        }
        
        // Set timeout
        DWORD timeout_ms = (timeout_seconds > 0 ? timeout_seconds : 30) * 1000;
        WinHttpSetTimeouts(hRequest, timeout_ms, timeout_ms, timeout_ms, timeout_ms);
        
        // Set authorization header
        std::string auth_header = "Authorization: Bearer " + access_token;
        std::wstring wauth_header(auth_header.begin(), auth_header.end());
        WinHttpAddRequestHeaders(hRequest, wauth_header.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);
        
        // Send request
        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, 
                               WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            DWORD error = GetLastError();
            std::string error_msg = "Failed to send HTTP request: " + GetWinHttpErrorMessage(error);
            SecurityUtils::LogMessage("WinHttpSendRequest failed: " + error_msg);
            SetError(error_msg);
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            // Don't close session - it's pooled
            return response;
        }
        
        // Receive response
        if (!WinHttpReceiveResponse(hRequest, nullptr)) {
            DWORD error = GetLastError();
            std::string error_msg = "Failed to receive HTTP response: " + GetWinHttpErrorMessage(error);
            SecurityUtils::LogMessage("WinHttpReceiveResponse failed: " + error_msg);
            SetError(error_msg);
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            // Don't close session - it's pooled
            return response;
        }
        
        // Get status code
        DWORD status_code = 0;
        DWORD status_code_size = sizeof(status_code);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &status_code_size, 
                           WINHTTP_NO_HEADER_INDEX);
        response.status_code = static_cast<long>(status_code);
        
        // Read response data
        DWORD bytes_available = 0;
        do {
            if (!WinHttpQueryDataAvailable(hRequest, &bytes_available)) {
                break;
            }
            
            if (bytes_available == 0) break;
            
            std::vector<char> buffer(bytes_available);
            DWORD bytes_read = 0;
            if (WinHttpReadData(hRequest, buffer.data(), bytes_available, &bytes_read)) {
                response.data.append(buffer.data(), bytes_read);
            }
        } while (bytes_available > 0);
        
        response.success = (status_code >= 200 && status_code < 300);
        
        // Validate response is from Patreon (not a proxy/local attack)
        if (response.success && !ValidatePatreonResponse(response.data)) {
            SetError("Invalid response format - possible proxy attack");
            response.success = false;
        }
        
        // Close request and connect handles, but keep session for reuse
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        // Session is pooled - don't close it
    }
    catch (...) {
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        // Don't close session in exception handler - it's pooled
        SetError("Exception during HTTP request");
    }
    
    return response;
}

// Windows implementation of POST request to server (for OAuth2 operations)
HttpResponse MakeServerRequest_Windows(const std::string& url, const std::string& post_data, int timeout_seconds) {
    HttpResponse response;
    response.success = false;
    response.status_code = 0;
    
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hRequest = nullptr;
    
    try {
        // Reuse pooled session instead of creating new one
        hSession = GetServerSession();
        if (!hSession) {
            SetError("Failed to get WinHTTP session");
            return response;
        }
        
        // Parse URL
        std::wstring wurl(url.begin(), url.end());
        URL_COMPONENTSW urlComp;
        ZeroMemory(&urlComp, sizeof(urlComp));
        urlComp.dwStructSize = sizeof(urlComp);
        urlComp.dwSchemeLength = -1;
        urlComp.dwHostNameLength = -1;
        urlComp.dwUrlPathLength = -1;
        
        if (!WinHttpCrackUrl(wurl.c_str(), static_cast<DWORD>(wurl.length()), 0, &urlComp)) {
            SetError("Failed to parse URL");
            return response;
        }
        
        std::wstring hostname(urlComp.lpszHostName, urlComp.dwHostNameLength);
        std::wstring path(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
        
        hConnect = WinHttpConnect(hSession, hostname.c_str(), urlComp.nPort, 0);
        if (!hConnect) {
            // Don't close session - it's pooled
            SetError("Failed to connect to server");
            return response;
        }
        
        DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
        hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(), nullptr, 
                                     WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            // Don't close session - it's pooled
            SetError("Failed to create HTTP request");
            return response;
        }
        
        // Set timeout
        DWORD timeout_ms = (timeout_seconds > 0 ? timeout_seconds : 30) * 1000;
        WinHttpSetTimeouts(hRequest, timeout_ms, timeout_ms, timeout_ms, timeout_ms);
        
        // Set Content-Type header
        std::wstring content_type = L"Content-Type: application/json; charset=utf-8\r\n";
        WinHttpAddRequestHeaders(hRequest, content_type.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);
        
        // Send request with POST data (as UTF-8)
        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, 
                               const_cast<LPVOID>(static_cast<const void*>(post_data.c_str())),
                               static_cast<DWORD>(post_data.length()),
                               static_cast<DWORD>(post_data.length()), 0)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            // Don't close session - it's pooled
            SetError("Failed to send HTTP request");
            return response;
        }
        
        // Receive response
        if (!WinHttpReceiveResponse(hRequest, nullptr)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            // Don't close session - it's pooled
            SetError("Failed to receive HTTP response");
            return response;
        }
        
        // Get status code
        DWORD status_code = 0;
        DWORD status_code_size = sizeof(status_code);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &status_code_size, 
                           WINHTTP_NO_HEADER_INDEX);
        response.status_code = static_cast<long>(status_code);
        
        // Read response data
        DWORD bytes_available = 0;
        do {
            if (!WinHttpQueryDataAvailable(hRequest, &bytes_available)) {
                break;
            }
            
            if (bytes_available == 0) break;
            
            std::vector<char> buffer(bytes_available);
            DWORD bytes_read = 0;
            if (WinHttpReadData(hRequest, buffer.data(), bytes_available, &bytes_read)) {
                response.data.append(buffer.data(), bytes_read);
            }
        } while (bytes_available > 0);
        
        response.success = (status_code >= 200 && status_code < 300);
        
        // Close request and connect handles, but keep session for reuse
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        // Session is pooled - don't close it
    }
    catch (...) {
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        // Don't close session in exception handler - it's pooled
        SetError("Exception during HTTP request");
    }
    
    return response;
}

// Windows implementation of opening browser
int OpenBrowser_Windows(const std::string& url) {
    try {
        std::wstring wurl(url.begin(), url.end());
        HINSTANCE result = ShellExecuteW(nullptr, L"open", wurl.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        
        // ShellExecute returns value > 32 on success
        if (reinterpret_cast<INT_PTR>(result) > 32) {
            return PATREON_SUCCESS;
        } else {
            SetError("Failed to open browser");
            return PATREON_ERROR_UNKNOWN;
        }
    }
    catch (...) {
        SetError("Exception while opening browser");
        return PATREON_ERROR_UNKNOWN;
    }
}

