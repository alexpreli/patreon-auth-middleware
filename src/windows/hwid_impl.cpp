#include "../../include/patreon_auth.h"
#include <windows.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <sstream>
#include <iomanip>
#pragma comment(lib, "iphlpapi.lib")

// Windows implementation of HWID generation
std::string GenerateHWID_Windows() {
    std::stringstream hwid;
    
    // Windows: Use CPU ID + Volume Serial Number + MAC Address
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    hwid << std::hex << std::setfill('0');
    hwid << std::setw(8) << cpuInfo[0];
    hwid << std::setw(8) << cpuInfo[1];
    hwid << std::setw(8) << cpuInfo[2];
    hwid << std::setw(8) << cpuInfo[3];
    
    // Volume Serial Number
    DWORD volumeSerial = 0;
    if (GetVolumeInformationA("C:\\", nullptr, 0, &volumeSerial, nullptr, nullptr, nullptr, 0)) {
        hwid << std::setw(8) << volumeSerial;
    }
    
    // MAC Address (first network adapter)
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD bufLen = sizeof(adapterInfo);
    if (GetAdaptersInfo(adapterInfo, &bufLen) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO pAdapterInfo = adapterInfo;
        if (pAdapterInfo) {
            for (int i = 0; i < 6; i++) {
                hwid << std::setw(2) << static_cast<int>(pAdapterInfo->Address[i]);
            }
        }
    }
    
    return hwid.str();
}

