#include "../../include/patreon_auth.h"
#include "../http_response.h"
#include <curl/curl.h>
#include <string>
#include <cstring>
#include <cstdlib>
#include <sys/wait.h>
#include <unistd.h>
#include <mutex>
#include <chrono>

// Forward declarations - these are defined in patreon_client.cpp
void SetError(const std::string& error);
bool ValidateHostname(const std::string& hostname);
bool ValidatePatreonResponse(const std::string& response_data);

// Connection pooling: Reuse libcurl handles to avoid TLS handshake on every request
static CURL* g_patreonCurl = nullptr;
static CURL* g_serverCurl = nullptr;
static std::mutex g_patreonCurlMutex;
static std::mutex g_serverCurlMutex;
static std::chrono::steady_clock::time_point g_patreonCurlLastUsed;
static std::chrono::steady_clock::time_point g_serverCurlLastUsed;
static const int CURL_IDLE_TIMEOUT_SECONDS = 300; // Close handle after 5 minutes of inactivity

// Helper function to get or create Patreon API curl handle
static CURL* GetPatreonCurl() {
    std::lock_guard<std::mutex> lock(g_patreonCurlMutex);
    
    auto now = std::chrono::steady_clock::now();
    
    // Check if handle exists and is still valid
    if (g_patreonCurl) {
        auto idle_time = std::chrono::duration_cast<std::chrono::seconds>(
            now - g_patreonCurlLastUsed).count();
        
        // If handle is too old, close it and create a new one
        if (idle_time > CURL_IDLE_TIMEOUT_SECONDS) {
            curl_easy_cleanup(g_patreonCurl);
            g_patreonCurl = nullptr;
        }
    }
    
    // Create new handle if needed
    if (!g_patreonCurl) {
        g_patreonCurl = curl_easy_init();
        if (g_patreonCurl) {
            // Set common options for Patreon API
            curl_easy_setopt(g_patreonCurl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(g_patreonCurl, CURLOPT_SSL_VERIFYHOST, 2L);
            curl_easy_setopt(g_patreonCurl, CURLOPT_TIMEOUT, 30L);
            curl_easy_setopt(g_patreonCurl, CURLOPT_CONNECTTIMEOUT, 30L);
            // Enable connection reuse
            curl_easy_setopt(g_patreonCurl, CURLOPT_TCP_KEEPALIVE, 1L);
            curl_easy_setopt(g_patreonCurl, CURLOPT_TCP_KEEPIDLE, 60L);
            curl_easy_setopt(g_patreonCurl, CURLOPT_TCP_KEEPINTVL, 10L);
        }
    }
    
    if (g_patreonCurl) {
        g_patreonCurlLastUsed = now;
    }
    
    return g_patreonCurl;
}

// Helper function to get or create server curl handle
static CURL* GetServerCurl() {
    std::lock_guard<std::mutex> lock(g_serverCurlMutex);
    
    auto now = std::chrono::steady_clock::now();
    
    // Check if handle exists and is still valid
    if (g_serverCurl) {
        auto idle_time = std::chrono::duration_cast<std::chrono::seconds>(
            now - g_serverCurlLastUsed).count();
        
        // If handle is too old, close it and create a new one
        if (idle_time > CURL_IDLE_TIMEOUT_SECONDS) {
            curl_easy_cleanup(g_serverCurl);
            g_serverCurl = nullptr;
        }
    }
    
    // Create new handle if needed
    if (!g_serverCurl) {
        g_serverCurl = curl_easy_init();
        if (g_serverCurl) {
            // Set common options for server requests
            curl_easy_setopt(g_serverCurl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(g_serverCurl, CURLOPT_SSL_VERIFYHOST, 2L);
            curl_easy_setopt(g_serverCurl, CURLOPT_TIMEOUT, 30L);
            curl_easy_setopt(g_serverCurl, CURLOPT_CONNECTTIMEOUT, 30L);
            // Enable connection reuse
            curl_easy_setopt(g_serverCurl, CURLOPT_TCP_KEEPALIVE, 1L);
            curl_easy_setopt(g_serverCurl, CURLOPT_TCP_KEEPIDLE, 60L);
            curl_easy_setopt(g_serverCurl, CURLOPT_TCP_KEEPINTVL, 10L);
        }
    }
    
    if (g_serverCurl) {
        g_serverCurlLastUsed = now;
    }
    
    return g_serverCurl;
}

// Write callback for libcurl
size_t WriteCallback_Linux(void* contents, size_t size, size_t nmemb, void* userp) {
    HttpResponse* response = static_cast<HttpResponse*>(userp);
    size_t total_size = size * nmemb;
    response->data.append(static_cast<char*>(contents), total_size);
    return total_size;
}

// Linux implementation of HTTP request using libcurl
HttpResponse MakePatreonRequest_Linux(const std::string& url, const std::string& access_token, int timeout_seconds) {
    HttpResponse response;
    response.success = false;
    response.status_code = 0;
    
    // Reuse pooled curl handle instead of creating new one
    CURL* curl = GetPatreonCurl();
    if (!curl) {
        SetError("Failed to get libcurl handle");
        return response;
    }
    
    // Reset response data for this request
    response.data.clear();
    
    struct curl_slist* headers = nullptr;
    std::string auth_header = "Authorization: Bearer " + access_token;
    headers = curl_slist_append(headers, auth_header.c_str());
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    // Set request-specific options (these can change per request)
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback_Linux);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_seconds > 0 ? timeout_seconds : 30);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, timeout_seconds > 0 ? timeout_seconds : 30);
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status_code);
        response.success = (response.status_code >= 200 && response.status_code < 300);
        
        // Validate response is from Patreon (not a proxy/local attack)
        if (response.success && !ValidatePatreonResponse(response.data)) {
            SetError("Invalid response format - possible proxy attack");
            response.success = false;
        }
        
        // Validate hostname from URL
        char* effective_url = nullptr;
        if (curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective_url) == CURLE_OK && effective_url) {
            std::string url_str(effective_url);
            // Extract hostname from URL
            size_t protocol_end = url_str.find("://");
            if (protocol_end != std::string::npos) {
                size_t host_start = protocol_end + 3;
                size_t host_end = url_str.find("/", host_start);
                if (host_end == std::string::npos) host_end = url_str.length();
                std::string hostname = url_str.substr(host_start, host_end - host_start);
                
                // Remove port if present
                size_t port_pos = hostname.find(":");
                if (port_pos != std::string::npos) {
                    hostname = hostname.substr(0, port_pos);
                }
                
                if (!ValidateHostname(hostname)) {
                    SetError("Invalid hostname - possible MITM attack");
                    response.success = false;
                }
            }
        }
    } else if (res == CURLE_OPERATION_TIMEDOUT) {
        SetError("Network timeout");
        response.status_code = 0;
    } else {
        SetError("Network error: " + std::string(curl_easy_strerror(res)));
        response.status_code = 0;
    }
    
    // Clean up headers (but keep curl handle for reuse)
    curl_slist_free_all(headers);
    // Don't cleanup curl - it's pooled
    
    return response;
}

// Linux implementation of POST request to server (for OAuth2 operations)
HttpResponse MakeServerRequest_Linux(const std::string& url, const std::string& post_data, int timeout_seconds) {
    HttpResponse response;
    response.success = false;
    response.status_code = 0;
    
    // Reuse pooled curl handle instead of creating new one
    CURL* curl = GetServerCurl();
    if (!curl) {
        SetError("Failed to get libcurl handle");
        return response;
    }
    
    // Reset response data for this request
    response.data.clear();
    
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    // Set request-specific options (these can change per request)
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, post_data.length());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback_Linux);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_seconds > 0 ? timeout_seconds : 30);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, timeout_seconds > 0 ? timeout_seconds : 30);
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status_code);
        response.success = (response.status_code >= 200 && response.status_code < 300);
    } else if (res == CURLE_OPERATION_TIMEDOUT) {
        SetError("Network timeout");
        response.status_code = 0;
    } else {
        SetError("Network error: " + std::string(curl_easy_strerror(res)));
        response.status_code = 0;
    }
    
    // Clean up headers (but keep curl handle for reuse)
    curl_slist_free_all(headers);
    // Don't cleanup curl - it's pooled
    
    return response;
}

// Linux implementation of opening browser
int OpenBrowser_Linux(const std::string& url) {
    try {
        // Try xdg-open first (most common)
        int result = system(("xdg-open \"" + url + "\" > /dev/null 2>&1 &").c_str());
        if (result == 0 || WEXITSTATUS(result) == 0) {
            return PATREON_SUCCESS;
        }
        
        // Try alternatives
        const char* browsers[] = {
            "xdg-open",
            "x-www-browser",
            "firefox",
            "google-chrome",
            "chromium",
            "opera",
            nullptr
        };
        
        for (int i = 0; browsers[i] != nullptr; i++) {
            std::string cmd = std::string(browsers[i]) + " \"" + url + "\" > /dev/null 2>&1 &";
            result = system(cmd.c_str());
            if (result == 0 || WEXITSTATUS(result) == 0) {
                return PATREON_SUCCESS;
            }
        }
        
        SetError("Failed to open browser - no suitable browser found");
        return PATREON_ERROR_UNKNOWN;
    }
    catch (...) {
        SetError("Exception while opening browser");
        return PATREON_ERROR_UNKNOWN;
    }
}

