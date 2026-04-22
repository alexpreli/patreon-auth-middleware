/**
 * Example usage of Patreon Auth Middleware in TypeScript (Node.js)
 * This example uses the CLI tool via child_process
 * 
 * To use this file:
 * 1. Install TypeScript: npm install -g typescript
 * 2. Compile: tsc example_typescript.ts
 * 3. Run: node example_typescript.js
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';

const execPromise = promisify(exec);

// Path to the CLI tool (adjust based on your platform)
const CLI_PATH = process.platform === 'win32'
    ? path.join(__dirname, '..', 'build', 'Release', 'patreon_auth_cli.exe')
    : path.join(__dirname, '..', 'build', 'patreon_auth_cli');

interface VerifyResult {
    success: boolean;
    message: string;
    data?: string;
}

interface MemberInfo {
    [key: string]: any;
}

/**
 * Verify Patreon member status
 */
async function verifyMember(accessToken: string, tierId: number = 0): Promise<VerifyResult> {
    try {
        const args = ['--user-token', accessToken];
        if (tierId > 0) {
            args.push('--tier', tierId.toString());
        }
        
        const { stdout, stderr } = await execPromise(`"${CLI_PATH}" ${args.join(' ')}`);
        
        return {
            success: true,
            message: 'Member is active',
            data: stdout
        };
    } catch (error: any) {
        const exitCode = error.code;
        
        switch (exitCode) {
            case 0:
                return { success: true, message: 'Member is active' };
            case 1:
                return { success: false, message: 'Member is not active or not subscribed' };
            case 2:
                throw new Error('Invalid input parameters');
            case 3:
                throw new Error('Network error');
            case 4:
                throw new Error('Invalid or expired token');
            case 5:
                throw new Error('Invalid API response');
            case 6:
                throw new Error('Memory allocation error');
            default:
                throw new Error(error.stderr || 'Unknown error');
        }
    }
}

/**
 * Get detailed member information
 */
async function getMemberInfo(accessToken: string): Promise<MemberInfo> {
    try {
        const { stdout } = await execPromise(`"${CLI_PATH}" --user-token "${accessToken}" --info`);
        
        return JSON.parse(stdout);
    } catch (error: any) {
        if (error.code === 0) {
            try {
                return JSON.parse(error.stdout);
            } catch (e) {
                throw new Error('Invalid JSON response');
            }
        }
        throw new Error(`Failed to get member info: ${error.stderr || error.message}`);
    }
}

/**
 * Check if user has access to a specific tier
 */
async function checkTierAccess(accessToken: string, tierId: number): Promise<boolean> {
    const result = await verifyMember(accessToken, tierId);
    return result.success;
}

/**
 * Main example function
 */
async function main(): Promise<void> {
    const args = process.argv.slice(2);
    
    if (args.length < 1) {
        console.error('Usage: node example_typescript.js <access_token> [tier_id]');
        process.exit(1);
    }
    
    const accessToken = args[0];
    const tierId = args[1] ? parseInt(args[1]) : 0;
    
    console.log('Verifying Patreon membership...\n');
    
    try {
        // Basic verification
        const verifyResult = await verifyMember(accessToken, tierId);
        
        if (verifyResult.success) {
            console.log('✓ SUCCESS: User is an active Patreon member!');
        } else {
            console.log('X User is not an active member');
            console.log('Message:', verifyResult.message);
        }
        
        // Get detailed member information
        console.log('\nFetching detailed member information...');
        const memberInfo = await getMemberInfo(accessToken);
        console.log('Member Info:', JSON.stringify(memberInfo, null, 2));
        
        // Check specific tier access (example)
        if (tierId === 0) {
            console.log('\nChecking tier access (Tier ID: 12345)...');
            const hasTierAccess = await checkTierAccess(accessToken, 12345);
            console.log(`User ${hasTierAccess ? 'has' : 'does not have'} access to tier 12345`);
        }
        
    } catch (error: any) {
        console.error('Error:', error.message);
        process.exit(1);
    }
}

// Run if executed directly
if (require.main === module) {
    main();
}

// Export functions for use in other modules
export {
    verifyMember,
    getMemberInfo,
    checkTierAccess,
    VerifyResult,
    MemberInfo
};

