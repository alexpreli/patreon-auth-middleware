#!/usr/bin/env python3
"""
Production script to calculate SHA256 hashes of critical functions.
This script extracts function code from the compiled binary and calculates hashes.

Usage:
    python calculate_hashes.py <binary_path> <function_name> [output_file]

For Windows:
    python calculate_hashes.py patreon_auth.dll PATREON_VerifyMember function_hashes.h

For Linux:
    python calculate_hashes.py libpatreon_auth.so PATREON_VerifyMember function_hashes.h
"""

import sys
import hashlib
import subprocess
import os
import re

def extract_function_bytes_windows(binary_path, function_name):
    """Extract function bytes from Windows PE binary using dumpbin."""
    try:
        # Use dumpbin to disassemble
        result = subprocess.run(
            ['dumpbin', '/disasm', binary_path],
            capture_output=True,
            text=True,
            check=False
        )
        
        if result.returncode != 0:
            # Try alternative: use objdump if available
            result = subprocess.run(
                ['objdump', '-d', binary_path],
                capture_output=True,
                text=True,
                check=False
            )
        
        # Parse output to find function
        lines = result.stdout.split('\n')
        in_function = False
        function_bytes = []
        
        for line in lines:
            if function_name in line and ':' in line:
                in_function = True
                continue
            
            if in_function:
                # Check for function end (empty line or next function)
                if not line.strip() or (':' in line and function_name not in line):
                    break
                
                # Extract hex bytes from disassembly
                # Format: "  401000: 48 83 ec 28     sub    rsp, 28h"
                match = re.search(r':\s+((?:[0-9a-fA-F]{2}\s+)+)', line)
                if match:
                    hex_bytes = match.group(1).split()
                    function_bytes.extend([int(b, 16) for b in hex_bytes])
        
        return bytes(function_bytes) if function_bytes else None
        
    except Exception as e:
        print(f"Error extracting function: {e}", file=sys.stderr)
        return None

def extract_function_bytes_linux(binary_path, function_name):
    """Extract function bytes from Linux ELF binary using objdump."""
    try:
        result = subprocess.run(
            ['objdump', '-d', binary_path],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Parse output to find function
        lines = result.stdout.split('\n')
        in_function = False
        function_bytes = []
        
        for line in lines:
            if f'<{function_name}>:' in line or f'<{function_name}@plt>:' in line:
                in_function = True
                continue
            
            if in_function:
                # Check for function end
                if line.strip() == '' or '<' in line and '>:' in line:
                    break
                
                # Extract hex bytes
                # Format: "  401000: 48 83 ec 28     sub    rsp, 28"
                match = re.search(r':\s+((?:[0-9a-f]{2}\s+)+)', line)
                if match:
                    hex_bytes = match.group(1).split()
                    function_bytes.extend([int(b, 16) for b in hex_bytes])
        
        return bytes(function_bytes) if function_bytes else None
        
    except Exception as e:
        print(f"Error extracting function: {e}", file=sys.stderr)
        return None

def calculate_sha256(data):
    """Calculate SHA256 hash of data."""
    return hashlib.sha256(data).digest()

def format_hash_c_array(hash_bytes):
    """Format hash as C array initializer."""
    return ','.join(f'0x{b:02x}' for b in hash_bytes)

def main():
    if len(sys.argv) < 3:
        print("Usage: python calculate_hashes.py <binary_path> <function_name> [output_file]")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    function_name = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    if not os.path.exists(binary_path):
        print(f"Error: Binary not found: {binary_path}", file=sys.stderr)
        sys.exit(1)
    
    # Determine platform
    is_windows = sys.platform == 'win32'
    
    # Extract function bytes
    if is_windows:
        function_bytes = extract_function_bytes_windows(binary_path, function_name)
    else:
        function_bytes = extract_function_bytes_linux(binary_path, function_name)
    
    if not function_bytes:
        print(f"Error: Could not extract function {function_name}", file=sys.stderr)
        sys.exit(1)
    
    # Calculate hash
    hash_bytes = calculate_sha256(function_bytes)
    hash_str = format_hash_c_array(hash_bytes)
    
    # Output
    if output_file:
        with open(output_file, 'w') as f:
            f.write(f"// Auto-generated hash for {function_name}\n")
            f.write(f"// Binary: {binary_path}\n")
            f.write(f"// Function size: {len(function_bytes)} bytes\n")
            f.write(f"// Hash: {hash_bytes.hex()}\n\n")
            f.write(f"#define {function_name.upper()}_HASH {{{hash_str}}}\n")
        print(f"Hash written to {output_file}")
    else:
        print(f"Function: {function_name}")
        print(f"Size: {len(function_bytes)} bytes")
        print(f"Hash: {hash_bytes.hex()}")
        print(f"C Array: {{{hash_str}}}")

if __name__ == '__main__':
    main()

