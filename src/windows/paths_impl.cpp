#include "../../include/patreon_auth.h"
#include <windows.h>
#include <shlobj.h>
#include <string>

// Windows implementation of GetStoragePath
std::string GetStoragePath_Windows() {
    std::string path;
    
    char appdata_path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, appdata_path))) {
        path = std::string(appdata_path) + "\\PatreonAuth";
        CreateDirectoryA(path.c_str(), nullptr);
        path += "\\licenses.dat";
    } else {
        path = "licenses.dat"; // Fallback to current directory
    }
    
    return path;
}

// Windows implementation of EnsureDirectoryExists
void EnsureDirectoryExists_Windows(const std::string& filepath) {
    size_t pos = filepath.find_last_of("/\\");
    if (pos != std::string::npos) {
        std::string dir = filepath.substr(0, pos);
        CreateDirectoryA(dir.c_str(), nullptr);
    }
}

