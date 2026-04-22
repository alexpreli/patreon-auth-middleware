#!/bin/bash
# Build script for Linux/Unix

set -e

echo "Building Patreon Auth Middleware..."

# Check for required dependencies
if ! command -v cmake &> /dev/null; then
    echo "Error: CMake is not installed. Please install it first."
    exit 1
fi

if ! pkg-config --exists libcurl; then
    echo "Warning: libcurl development package not found."
    echo "Please install it: sudo apt-get install libcurl4-openssl-dev"
    echo "or: sudo yum install libcurl-devel"
    exit 1
fi

# Create build directory
mkdir -p build
cd build

# Configure and build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j$(nproc)

echo "Build successful!"
echo "Output files:"
echo "  Library: $(pwd)/libpatreon_auth.so"
echo "  CLI: $(pwd)/patreon_auth_cli"

cd ..

