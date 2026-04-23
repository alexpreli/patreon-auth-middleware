# Building Instructions

## Quick Start


### Build from Source

To build this project, follow the instructions below.

## Prerequisites

### Windows
- **Visual Studio 2019 or later** (with C++ desktop development workload)
  - Download from: https://visualstudio.microsoft.com/downloads/
  - Select "Desktop development with C++" workload during installation
- **CMake 3.12 or higher**
  - Download from: https://cmake.org/download/
  - Or install via: `choco install cmake` (if using Chocolatey)
- **Windows SDK** (usually included with Visual Studio)

### Linux/Unix
- **GCC or Clang compiler** with C++11 support
  - Debian/Ubuntu: `sudo apt-get install build-essential`
  - Fedora: `sudo dnf install gcc-c++`
- **CMake 3.12 or higher**
  - Debian/Ubuntu: `sudo apt-get install cmake`
  - Fedora: `sudo dnf install cmake`
- **libcurl development libraries**:
  - Debian/Ubuntu: `sudo apt-get install libcurl4-openssl-dev`
  - Red Hat/CentOS: `sudo yum install libcurl-devel`
  - Fedora: `sudo dnf install libcurl-devel`
  - Arch: `sudo pacman -S curl`

## Build Commands

### Windows

**PowerShell (Recommended):**
```powershell
# Create build directory
mkdir build
cd build

# Configure CMake (adjust Visual Studio version if needed)
cmake .. -G "Visual Studio 17 2022" -A x64

# Build Release
cmake --build . --config Release
```

**Command Prompt:**
```batch
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

**For x86 (32-bit):**
```powershell
cmake .. -G "Visual Studio 17 2022" -A Win32
cmake --build . --config Release
```

### Linux/Unix

```bash
# Create build directory
mkdir build
cd build

# Configure CMake
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build (use all CPU cores)
cmake --build . -j$(nproc)

# Alternative: Specify number of cores manually
# cmake --build . -j4
```

## Output Files

After building, you'll find the compiled files:

**Windows:**
- **Library**: `build\Release\patreon_auth.dll`
- **CLI Tool**: `build\Release\patreon_auth_cli.exe`
- **Header**: `include\patreon_auth.h` (source directory)

**Linux/Unix:**
- **Library**: `build/libpatreon_auth.so`
- **CLI Tool**: `build/patreon_auth_cli`
- **Header**: `include/patreon_auth.h` (source directory)

## Building Examples

To build the example programs:

```bash
cd build
cmake --build . --target patreon_auth_cli
```

Or compile examples manually:
```bash
# C++ example
g++ -std=c++11 examples/example_cpp.cpp -L./build -lpatreon_auth -o example_cpp

# C example
gcc examples/example_c.c -L./build -lpatreon_auth -o example_c
```

## Installation

To install system-wide (optional):

```bash
cd build
sudo cmake --install . --prefix /usr/local
```

This installs:
- Library to `/usr/local/lib` (or `C:\Program Files\PatreonAuth\lib` on Windows)
- Header to `/usr/local/include` (or `C:\Program Files\PatreonAuth\include` on Windows)
- CLI to `/usr/local/bin` (or `C:\Program Files\PatreonAuth\bin` on Windows)

## Production Build: Function Integrity Hashes

For production builds, you should calculate SHA256 hashes of critical functions to enable integrity verification. This prevents code patching and tampering.

### Step 1: Initial Build

First, build the library normally:

```bash
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

### Step 2: Calculate Function Hashes

After the first build, calculate hashes for critical functions:

**Windows:**
```powershell
# Install Python if not already installed
python scripts/calculate_hashes.py build\Release\patreon_auth.dll PATREON_VerifyMember
python scripts/calculate_hashes.py build\Release\patreon_auth.dll PATREON_GetMemberInfo
```

**Linux:**
```bash
python3 scripts/calculate_hashes.py build/libpatreon_auth.so PATREON_VerifyMember
python3 scripts/calculate_hashes.py build/libpatreon_auth.so PATREON_GetMemberInfo
```

The script will output hash values in C array format.

### Step 3: Rebuild with Hashes

Rebuild the library with the calculated hashes:

**Windows:**
```powershell
cmake .. -DPATREON_VERIFY_MEMBER_HASH_VALUE="{0x12,0x34,0x56,...}" -DPATREON_GET_MEMBER_INFO_HASH_VALUE="{0xab,0xcd,0xef,...}"
cmake --build . --config Release
```

**Linux:**
```bash
cmake .. -DPATREON_VERIFY_MEMBER_HASH_VALUE="{0x12,0x34,0x56,...}" -DPATREON_GET_MEMBER_INFO_HASH_VALUE="{0xab,0xcd,0xef,...}"
cmake --build . -j$(nproc)
```

### Alternative: Manual Hash Calculation

If the Python script doesn't work, you can manually extract function code:

**Windows (using dumpbin):**
```powershell
dumpbin /disasm /out:disasm.txt build\Release\patreon_auth.dll
# Extract function bytes from disasm.txt, calculate SHA256
```

**Linux (using objdump):**
```bash
objdump -d build/libpatreon_auth.so > disasm.txt
# Extract function bytes from disasm.txt, calculate SHA256
```

Then use an online SHA256 calculator or Python:
```python
import hashlib
hash_bytes = hashlib.sha256(function_bytes).digest()
print(','.join(f'0x{b:02x}' for b in hash_bytes))
```

### Important Notes

- **Hash values must be recalculated after each code change** that affects the functions
- **Zero hashes (default) disable integrity checks** - this is acceptable for development but not for production
- **PDB files (Windows) or DWARF info (Linux) improve function size detection** - ensure debug info is generated
- **The integrity check will fail if the binary is patched or modified** - this is the intended behavior

## Troubleshooting

### Windows: "Cannot find winhttp.lib"
- Ensure Windows SDK is installed
- The library should be automatically linked via `#pragma comment(lib, "winhttp.lib")`

### Linux: "Cannot find libcurl"
- Install libcurl development package (see Prerequisites)
- Verify with: `pkg-config --exists libcurl && echo "OK"`

### CMake: "No CMAKE_CXX_COMPILER could be found"
- Install a C++ compiler (Visual Studio on Windows, build-essential on Linux)
- On Windows, ensure Visual Studio C++ tools are installed

### Linking Errors
- Ensure the library is in your library path
- On Linux, you may need to run `sudo ldconfig` after installation
- On Windows, ensure the DLL is in the same directory as your executable or in PATH

