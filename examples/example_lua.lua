-- Example usage of Patreon Auth Middleware in Lua
-- This example uses the CLI tool via io.popen
-- Requires Lua 5.1+ (tested with Lua 5.3+)

local os = require('os')
local io = require('io')
local json = require('json') -- You may need to install a JSON library like lua-cjson

-- Detect platform and set CLI path
local function getCliPath()
    local platform = package.config:sub(1,1) == '\\' and 'windows' or 'unix'
    local scriptDir = debug.getinfo(1, "S").source:match("@?(.*/)")
    
    if platform == 'windows' then
        return scriptDir .. '../build/Release/patreon_auth_cli.exe'
    else
        return scriptDir .. '../build/patreon_auth_cli'
    end
end

local CLI_PATH = getCliPath()

-- Simple JSON parser (basic implementation, consider using lua-cjson for production)
local function parseJson(str)
    -- This is a very basic JSON parser. For production, use lua-cjson or similar
    -- For now, we'll just return the raw string and let the user parse it
    return str
end

-- Verify Patreon member status
-- @param accessToken: Patron's/user's OAuth2 access token
-- @param tierId: Optional tier ID (0 for any tier)
-- @return: table with success (boolean), message (string), data (string)
function verifyMember(accessToken, tierId)
    tierId = tierId or 0
    
    local args = {'--user-token', accessToken}
    if tierId > 0 then
        table.insert(args, '--tier')
        table.insert(args, tostring(tierId))
    end
    
    local command = '"' .. CLI_PATH .. '"'
    for i, arg in ipairs(args) do
        command = command .. ' "' .. arg .. '"'
    end
    
    local handle = io.popen(command .. ' 2>&1')
    if not handle then
        return {
            success = false,
            message = 'Failed to execute CLI tool',
            error = 'CLI tool not found at ' .. CLI_PATH
        }
    end
    
    local output = handle:read('*a')
    local exitCode = handle:close()
    
    -- On Windows, exit code is in the return value
    -- On Unix, we need to check differently
    if exitCode == 0 or exitCode == true then
        return {
            success = true,
            message = 'Member is active',
            data = output
        }
    elseif exitCode == 1 then
        return {
            success = false,
            message = 'Member is not active or not subscribed'
        }
    elseif exitCode == 2 then
        return {
            success = false,
            message = 'Invalid input parameters',
            error = output
        }
    elseif exitCode == 3 then
        return {
            success = false,
            message = 'Network error',
            error = output
        }
    elseif exitCode == 4 then
        return {
            success = false,
            message = 'Invalid or expired token',
            error = output
        }
    elseif exitCode == 5 then
        return {
            success = false,
            message = 'Invalid API response',
            error = output
        }
    elseif exitCode == 6 then
        return {
            success = false,
            message = 'Memory allocation error',
            error = output
        }
    else
        return {
            success = false,
            message = 'Unknown error',
            error = output
        }
    end
end

-- Get detailed member information
-- @param accessToken: Patron's/user's OAuth2 access token
-- @return: table with member information
function getMemberInfo(accessToken)
    local command = '"' .. CLI_PATH .. '" --user-token "' .. accessToken .. '" --info 2>&1'
    
    local handle = io.popen(command)
    if not handle then
        return {
            success = false,
            error = 'Failed to execute CLI tool'
        }
    end
    
    local output = handle:read('*a')
    local exitCode = handle:close()
    
    if exitCode == 0 or exitCode == true then
        -- Try to parse JSON (you may want to use a proper JSON library)
        return {
            success = true,
            data = output,
            json = parseJson(output)
        }
    else
        return {
            success = false,
            error = output
        }
    end
end

-- Check if user has access to a specific tier
-- @param accessToken: Patron's/user's OAuth2 access token
-- @param tierId: Tier ID to check
-- @return: boolean
function checkTierAccess(accessToken, tierId)
    local result = verifyMember(accessToken, tierId)
    return result.success
end

-- Example usage
function main()
    local args = {...}
    
    if #args < 1 then
        print('Usage: lua example_lua.lua <access_token> [tier_id]')
        os.exit(1)
    end
    
    local accessToken = args[1]
    local tierId = args[2] and tonumber(args[2]) or 0
    
    print('Verifying Patreon membership...\n')
    
    -- Basic verification
    local verifyResult = verifyMember(accessToken, tierId)
    
    if verifyResult.success then
        print('✓ SUCCESS: User is an active Patreon member!')
    else
        print('X User is not an active member')
        print('Message: ' .. verifyResult.message)
        if verifyResult.error then
            print('Error: ' .. verifyResult.error)
        end
    end
    
    -- Get detailed member information
    print('\nFetching detailed member information...')
    local memberInfo = getMemberInfo(accessToken)
    
    if memberInfo.success then
        print('Member Info:')
        print(memberInfo.data)
    else
        print('Failed to get member info: ' .. (memberInfo.error or 'Unknown error'))
    end
    
    -- Check specific tier access (example)
    if tierId == 0 then
        print('\nChecking tier access (Tier ID: 12345)...')
        local hasTierAccess = checkTierAccess(accessToken, 12345)
        print('User ' .. (hasTierAccess and 'has' or 'does not have') .. ' access to tier 12345')
    end
end

-- Run if executed directly
if arg and #arg > 0 then
    main()
end

-- Export functions for use in other modules
return {
    verifyMember = verifyMember,
    getMemberInfo = getMemberInfo,
    checkTierAccess = checkTierAccess
}

