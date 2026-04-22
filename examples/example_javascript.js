// Example usage of Patreon Auth Middleware in JavaScript (Node.js)
// This example uses the CLI tool via child_process

const { exec } = require('child_process');
const path = require('path');
const util = require('util');

const execPromise = util.promisify(exec);

// Path to the CLI tool (adjust based on your platform)
const CLI_PATH = process.platform === 'win32'
    ? path.join(__dirname, '..', 'build', 'Release', 'patreon_auth_cli.exe')
    : path.join(__dirname, '..', 'build', 'patreon_auth_cli');

/**
 * Verify Patreon member status
 * @param {string} accessToken - Patron's/user's OAuth2 access token
 * @param {number} tierId - Optional tier ID (0 for any tier)
 * @returns {Promise<{success: boolean, message: string}>}
 */
async function verifyMember(accessToken, tierId = 0) {
    try {
        const args = ['--user-token', accessToken];
        if (tierId > 0) {
            args.push('--tier', tierId.toString());
        }

        const { stdout, stderr } = await execPromise(`"${CLI_PATH}" ${args.join(' ')}`);

        // Exit code 0 means success
        return {
            success: true,
            message: 'Member is active',
            data: stdout
        };
    } catch (error) {
        // Check exit code
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
                throw new Error(stderr || 'Unknown error');
        }
    }
}

/**
 * Get detailed member information
 * @param {string} accessToken - Patron's/user's OAuth2 access token
 * @returns {Promise<Object>}
 */
async function getMemberInfo(accessToken) {
    try {
        const { stdout } = await execPromise(`"${CLI_PATH}" --user-token "${accessToken}" --info`);

        // Parse JSON response
        const info = JSON.parse(stdout);
        return info;
    } catch (error) {
        if (error.code === 0) {
            // Try to parse even if there was an error object
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
 * @param {string} accessToken - Patron's/user's OAuth2 access token
 * @param {number} tierId - Tier ID to check
 * @returns {Promise<boolean>}
 */
async function checkTierAccess(accessToken, tierId) {
    const result = await verifyMember(accessToken, tierId);
    return result.success;
}

// Example usage
async function main() {
    if (process.argv.length < 3) {
        console.error('Usage: node example_javascript.js <access_token> [tier_id]');
        process.exit(1);
    }

    const accessToken = process.argv[2];
    const tierId = process.argv[3] ? parseInt(process.argv[3]) : 0;

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

    } catch (error) {
        console.error('Error:', error.message);
        process.exit(1);
    }
}

// Run if executed directly
if (require.main === module) {
    main();
}

// Export functions for use in other modules
module.exports = {
    verifyMember,
    getMemberInfo,
    checkTierAccess
};

