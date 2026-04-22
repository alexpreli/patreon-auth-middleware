#!/usr/bin/env python3
"""
Example usage of Patreon Auth Middleware in Python
This example uses the CLI tool via subprocess
"""

import subprocess
import json
import sys
import os
from pathlib import Path

# Path to the CLI tool (adjust based on your platform)
if sys.platform == 'win32':
    CLI_PATH = Path(__file__).parent.parent / 'build' / 'Release' / 'patreon_auth_cli.exe'
else:
    CLI_PATH = Path(__file__).parent.parent / 'build' / 'patreon_auth_cli'


def verify_member(access_token: str, tier_id: int = 0) -> dict:
    """
    Verify Patreon member status
    
    Args:
        access_token: Patron's/user's OAuth2 access token
        tier_id: Optional tier ID (0 for any tier)
    
    Returns:
        dict: {'success': bool, 'message': str, 'data': str}
    """
    try:
        args = [str(CLI_PATH), '--user-token', access_token]
        if tier_id > 0:
            args.extend(['--tier', str(tier_id)])
        
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            return {
                'success': True,
                'message': 'Member is active',
                'data': result.stdout
            }
        elif result.returncode == 1:
            return {
                'success': False,
                'message': 'Member is not active or not subscribed'
            }
        elif result.returncode == 2:
            raise ValueError('Invalid input parameters')
        elif result.returncode == 3:
            raise ConnectionError('Network error')
        elif result.returncode == 4:
            raise ValueError('Invalid or expired token')
        elif result.returncode == 5:
            raise ValueError('Invalid API response')
        elif result.returncode == 6:
            raise MemoryError('Memory allocation error')
        else:
            raise RuntimeError(result.stderr or 'Unknown error')
            
    except subprocess.TimeoutExpired:
        raise TimeoutError('Request timeout')
    except FileNotFoundError:
        raise FileNotFoundError(f'CLI tool not found at {CLI_PATH}. Please build the project first.')


def get_member_info(access_token: str) -> dict:
    """
    Get detailed member information
    
    Args:
        access_token: Patron's/user's OAuth2 access token
    
    Returns:
        dict: Member information as JSON
    """
    try:
        result = subprocess.run(
            [str(CLI_PATH), '--user-token', access_token, '--info'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            raise RuntimeError(result.stderr or 'Failed to get member info')
            
    except json.JSONDecodeError:
        raise ValueError('Invalid JSON response')
    except subprocess.TimeoutExpired:
        raise TimeoutError('Request timeout')
    except FileNotFoundError:
        raise FileNotFoundError(f'CLI tool not found at {CLI_PATH}. Please build the project first.')


def check_tier_access(access_token: str, tier_id: int) -> bool:
    """
    Check if user has access to a specific tier
    
    Args:
        access_token: Patron's/user's OAuth2 access token
        tier_id: Tier ID to check
    
    Returns:
        bool: True if user has access, False otherwise
    """
    result = verify_member(access_token, tier_id)
    return result['success']


def main():
    """Example usage"""
    if len(sys.argv) < 2:
        print('Usage: python example_python.py <access_token> [tier_id]', file=sys.stderr)
        sys.exit(1)
    
    access_token = sys.argv[1]
    tier_id = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    
    print('Verifying Patreon membership...\n')
    
    try:
        # Basic verification
        verify_result = verify_member(access_token, tier_id)
        
        if verify_result['success']:
            print('✓ SUCCESS: User is an active Patreon member!')
        else:
            print('X User is not an active member')
            print(f"Message: {verify_result['message']}")
        
        # Get detailed member information
        print('\nFetching detailed member information...')
        member_info = get_member_info(access_token)
        print('Member Info:')
        print(json.dumps(member_info, indent=2))
        
        # Check specific tier access (example)
        if tier_id == 0:
            print('\nChecking tier access (Tier ID: 12345)...')
            has_tier_access = check_tier_access(access_token, 12345)
            print(f"User {'has' if has_tier_access else 'does not have'} access to tier 12345")
        
    except Exception as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

