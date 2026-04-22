#include "../../include/patreon_auth.h"
#include <unistd.h>
#include <sys/utsname.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <cstdio>

// Linux implementation of HWID generation
std::string GenerateHWID_Linux() {
    std::stringstream hwid;
    
    // Linux/Unix: Use machine ID + MAC Address + CPU info
    // Machine ID (from /etc/machine-id or /var/lib/dbus/machine-id)
    FILE* machine_id_file = fopen("/etc/machine-id", "r");
    if (!machine_id_file) {
        machine_id_file = fopen("/var/lib/dbus/machine-id", "r");
    }
    if (machine_id_file) {
        char machine_id[64] = {0};
        if (fgets(machine_id, sizeof(machine_id), machine_id_file)) {
            // Remove newline
            size_t len = strlen(machine_id);
            if (len > 0 && machine_id[len-1] == '\n') {
                machine_id[len-1] = '\0';
            }
            hwid << machine_id;
        }
        fclose(machine_id_file);
    }
    
    // MAC Address (first non-loopback interface)
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == 0) {
        for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET) {
                struct sockaddr_ll* sll = (struct sockaddr_ll*)ifa->ifa_addr;
                if (!(ifa->ifa_flags & IFF_LOOPBACK) && sll->sll_halen > 0) {
                    for (int i = 0; i < sll->sll_halen && i < 6; i++) {
                        hwid << std::hex << std::setfill('0') << std::setw(2) 
                             << static_cast<int>(sll->sll_addr[i]);
                    }
                    break;
                }
            }
        }
        freeifaddrs(ifaddr);
    }
    
    // CPU info (from /proc/cpuinfo)
    FILE* cpuinfo = fopen("/proc/cpuinfo", "r");
    if (cpuinfo) {
        char line[256];
        while (fgets(line, sizeof(line), cpuinfo)) {
            if (strncmp(line, "processor", 9) == 0) {
                // Use first processor ID
                int processor_id = 0;
                if (sscanf(line, "processor : %d", &processor_id) == 1) {
                    hwid << std::hex << processor_id;
                    break;
                }
            }
        }
        fclose(cpuinfo);
    }
    
    return hwid.str();
}

