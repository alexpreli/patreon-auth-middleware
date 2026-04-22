@echo off
REM Build script for Windows - builds both x64 and x86
echo Building Patreon Auth Middleware for x64 and x86...

REM Build x64
echo.
echo ===== Building x64 =====
if not exist build\x64 mkdir build\x64
cd build\x64
cmake ..\.. -G "Visual Studio 17 2022" -A x64
if errorlevel 1 (
    echo CMake configuration failed for x64!
    cd ..\..
    exit /b 1
)
cmake --build . --config Release
if errorlevel 1 (
    echo Build failed for x64!
    cd ..\..
    exit /b 1
)
cd ..\..

REM Build x86
echo.
echo ===== Building x86 =====
if not exist build\x86 mkdir build\x86
cd build\x86
cmake ..\.. -G "Visual Studio 17 2022" -A Win32
if errorlevel 1 (
    echo CMake configuration failed for x86!
    cd ..\..
    exit /b 1
)
cmake --build . --config Release
if errorlevel 1 (
    echo Build failed for x86!
    cd ..\..
    exit /b 1
)
cd ..\..

echo.
echo Build successful!
echo x64 output: build\x64\Release
echo x86 output: build\x86\Release

