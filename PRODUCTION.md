# Production Deployment Guide

This guide covers important considerations for deploying this middleware in production environments, especially for   complex and advanced software.

## Security Features

### 1. Function Integrity Verification

The library uses SHA256 hashes to verify that critical functions haven't been patched or modified. This is essential for production deployments.

**Setup Process:**
1. Build the library normally
2. Calculate SHA256 hashes for `PATREON_VerifyMember` and `PATREON_GetMemberInfo`
3. Rebuild with the calculated hashes
4. The library will automatically verify function integrity at runtime

See `BUILDING.md` for detailed instructions on calculating hashes.

### 2. Anti-Patching Detection

The library includes multiple layers of anti-patching protection:

- **PDB/DWARF Integration**: Uses debug symbols to accurately determine function boundaries
- **Memory Protection Checks**: Verifies code sections are not writable
- **Hook Detection**: Detects common function hooking patterns (JMP, CALL, INT 3)
- **Tool Detection**: Identifies common debugging/patching tools

### 3. Anti-Debugging

Multiple anti-debugging techniques are employed:

- Windows: `IsDebuggerPresent()`, PEB checks, timing analysis
- Linux: `ptrace()` checks, `/proc/self/status` analysis, timing checks

### 4. License Management (HWID Binding)

For preventing account sharing:

- **BLOCK Policy**: Prevents access if HWID doesn't match
- **TRANSFER Policy**: Allows limited license transfers with cooldown periods
- Encrypted local storage for license data

## Production Checklist

### Before Deployment

- Calculate and set function integrity hashes (see [BUILDING.md](BUILDING.md))
- Test all security features (anti-debugging, anti-patching)
- Verify license management policies work as expected
- Test rate limiting to prevent DoS attacks
- Review and configure logging callbacks
- Test on target platforms (Windows/Linux)
- Verify SSL/TLS certificate validation
- Test with invalid tokens and error scenarios

### Build Configuration

For production builds, ensure:

```cmake
# Release build with optimizations
cmake .. -DCMAKE_BUILD_TYPE=Release

# Set function hashes (after first build)
cmake .. -DPATREON_VERIFY_MEMBER_HASH_VALUE="..." -DPATREON_GET_MEMBER_INFO_HASH_VALUE="..."

# Rebuild
cmake --build . --config Release
```

### Runtime Configuration

1. **Set License Policy** (if using license management):
   ```cpp
   PATREON_SetLicensePolicy(PATREON_LICENSE_POLICY_BLOCK); // or TRANSFER
   ```

2. **Configure Logging** (recommended for production):
   ```cpp
   void LogCallback(const char* message, void* user_data) {
       // Log to your logging system
       // DO NOT log sensitive information (tokens, etc.)
   }
   PATREON_SetLogCallback(LogCallback, nullptr);
   ```

3. **Handle Errors Gracefully**:
   ```cpp
   int result = PATREON_VerifyMember(token, nullptr, 0, 10);
   if (result != PATREON_SUCCESS) {
       char error[512];
       PATREON_GetLastError(error, sizeof(error));
       // Handle error appropriately
   }
   ```

## Important Security Notes

### Client-Side Limitations


**Recommendations:**
- Always implement server-side validation for critical operations
- Use this library as part of a multi-layered security approach
- Monitor for suspicious patterns (multiple failed verifications, etc.)
- Implement additional server-side rate limiting
- Log security events for analysis

### Function Hash Updates

**Critical**: Function hashes must be recalculated after:
- Any code changes to `PATREON_VerifyMember` or `PATREON_GetMemberInfo`
- Compiler version changes
- Optimization level changes
- Any modifications to the build process

### PDB/DWARF Files

For best results:
- **Windows**: Generate PDB files (default in Release builds with Visual Studio)
- **Linux**: Include DWARF debug info (`-g` flag, but strip symbols in final binary if needed)

The library will fall back to pattern matching if PDB/DWARF info is not available, but this is less accurate.

## Performance Considerations

- Function integrity checks are performed once at startup (cached)
- Anti-patching checks are lightweight and fast
- Rate limiting uses efficient map-based tracking
- License checks are in-memory (file I/O only on registration/transfer)

## Troubleshooting Production Issues

### Integrity Checks Failing

If integrity checks fail unexpectedly:

1. Verify function hashes are correctly set
2. Check if binary was modified after build
3. Ensure PDB/DWARF files are available (if using symbol-based detection)
4. Check for antivirus/security software modifying the binary

### False Positives (Debugging Tools Detected)

If legitimate debugging tools trigger false positives:

- The library is designed to be strict for production security
- Consider using a separate "debug" build with relaxed checks for development
- Use conditional compilation to disable checks in development builds

### License Transfer Issues

If license transfers are not working:

1. Check license policy setting
2. Verify transfer limits and cooldown periods
3. Check file permissions for license storage
4. Review logs for specific error messages

## Support and Maintenance

For production deployments:

- Keep the library updated with latest security patches
- Monitor for Patreon API changes
- Review security advisories regularly
