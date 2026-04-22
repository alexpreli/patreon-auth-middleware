#include "../../include/patreon_auth.h"
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>
#include <string>
#include <cstdlib>

// Linux implementation of GetStoragePath
std::string GetStoragePath_Linux() {
    std::string path;
    
    const char* home = getenv("HOME");
    if (home) {
        path = std::string(home) + "/.patreon_auth/licenses.dat";
    } else {
        struct passwd* pw = getpwuid(getuid());
        if (pw) {
            path = std::string(pw->pw_dir) + "/.patreon_auth/licenses.dat";
        } else {
            path = "licenses.dat"; // Fallback
        }
    }
    
    return path;
}

// Linux implementation of EnsureDirectoryExists
void EnsureDirectoryExists_Linux(const std::string& filepath) {
    size_t pos = filepath.find_last_of("/\\");
    if (pos != std::string::npos) {
        std::string dir = filepath.substr(0, pos);
        mkdir(dir.c_str(), 0755);
        // Create parent directories if needed
        size_t last_slash = dir.find_last_of('/');
        if (last_slash != std::string::npos && last_slash > 0) {
            std::string parent = dir.substr(0, last_slash);
            mkdir(parent.c_str(), 0755);
        }
    }
}

