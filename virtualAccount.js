import fs from 'fs'
import crypto from 'crypto'
import https from 'https'
import fetch from 'node-fetch'
import dotenv from 'dotenv'

// Load environment variables
dotenv.config()

// Configuration constants
const CONFIG = {
    privateKey: fs.readFileSync('key', 'utf-8'),
    clientId: process.env.CLIENT_ID || '',
    apiUrl: process.env.BASE_URL_DEVELOPMENT || '',
    clientSecret: process.env.CLIENT_SECRET || '',
    partnerId: process.env.PARTNER_ID || '',
    host: '103.214.54.198'
}

// Validate required environment variables
function validateConfig() {
    const required = ['CLIENT_ID', 'BASE_URL_DEVELOPMENT', 'CLIENT_SECRET', 'PARTNER_ID']
    const missing = required.filter(key => !process.env[key])

    if (missing.length > 0) {
        throw new Error(`Missing required environment variables: ${missing.join(', ')}`)
    }
}

/**
 * Generate current timestamp in required format
 * @returns {string} Formatted timestamp
 */
function getCurrentTimestamp() {
    const now = new Date()
    const pad = n => n.toString().padStart(2, '0')

    return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}T${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}+07:00`
}

/**
 * Create RSA signature for authentication
 * @returns {Object} signature and timestamp
 */
function createAuthSignature() {
    const timestamp = getCurrentTimestamp()
    const data = `${CONFIG.clientId}|${timestamp}`

    const sign = crypto.createSign('SHA256')
    sign.update(data)
    sign.end()

    const signature = sign.sign(CONFIG.privateKey, 'base64')

    return { signature, timestamp }
}

/**
 * Create HMAC signature for API requests
 * @param {string} httpMethod - HTTP method (GET, POST, etc.)
 * @param {string} endpointUrl - API endpoint path
 * @param {string} accessToken - Bearer token
 * @param {Object|string} requestBody - Request payload
 * @returns {Object} signature and timestamp
 */
function createHMACSignature(httpMethod, endpointUrl, accessToken, requestBody = '') {
    // Minify request body
    let minifiedBody = ''
    if (requestBody) {
        minifiedBody = typeof requestBody === 'object'
            ? JSON.stringify(requestBody).replace(/\s+/g, '')
            : requestBody.replace(/\s+/g, '')
    }

    // Create SHA-256 hash of minified body
    const bodyHash = crypto
        .createHash('sha256')
        .update(minifiedBody)
        .digest('hex')
        .toLowerCase()

    const timestamp = getCurrentTimestamp()

    // Create string to process for HMAC
    const stringToProcess = `${httpMethod.toUpperCase()}:${endpointUrl}:${accessToken}:${bodyHash}:${timestamp}`

    console.log('HMAC String to process:', stringToProcess)
    console.log('Body hash:', bodyHash)

    // Create HMAC-SHA512 signature
    const hmac = crypto.createHmac('sha512', CONFIG.clientSecret)
    hmac.update(stringToProcess)
    const signature = hmac.digest('base64')

    return { signature, timestamp }
}

/**
 * Create HTTPS agent with SSL verification disabled
 * @returns {https.Agent} HTTPS agent
 */
function createHttpsAgent() {
    return new https.Agent({
        rejectUnauthorized: false
    })
}

/**
 * Make HTTP request with error handling
 * @param {string} url - Request URL
 * @param {Object} options - Fetch options
 * @returns {Promise<Response>} Fetch response
 */
async function makeRequest(url, options) {
    try {
        const response = await fetch(url, {
            ...options,
            agent: createHttpsAgent()
        })

        console.log(`${options.method || 'GET'} ${url}`)
        console.log('Response Status:', response.status)

        return response
    } catch (error) {
        console.error('Request failed:', error.message)
        throw new Error(`HTTP request failed: ${error.message}`)
    }
}

/**
 * Authenticate and get access token
 * @returns {Promise<string>} Access token
 */
async function createAccessToken() {
    console.log('=== Creating Access Token ===')

    const { signature, timestamp } = createAuthSignature()
    const url = `${CONFIG.apiUrl}/services/va/management/auth.controller`

    console.log('Auth Request Details:')
    console.log('- URL:', url)
    console.log('- Timestamp:', timestamp)
    console.log('- Client ID:', CONFIG.clientId)

    const response = await makeRequest(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json; charset=UTF-8',
            'x-timestamp': timestamp,
            'x-signature': signature,
            'x-client-key': CONFIG.clientId,
        },
        body: JSON.stringify({
            grantType: "client_credentials"
        })
    })

    const data = await response.json()
    console.log('Auth Response:', data)

    if (!data.accessToken) {
        throw new Error(`Authentication failed: ${JSON.stringify(data)}`)
    }

    console.log('✅ Authentication successful')
    return data.accessToken
}

/**
 * Create virtual account
 * @param {string} accessToken - Bearer token
 * @returns {Promise<Object>} API response
 */
async function createVirtualAccount(accessToken) {
    console.log('\n=== Creating Virtual Account ===')

    const requestBody = {
        dataVa: "2310140002|MUHAMMAD AZRIL AL QURTHUBI|900000|2|SPP1124#450000!SPP 1224#450000|085219781422|example@mail.com\n2313080596|PIKRIHAIKAL MUBAROK|450000|1|SPP 1224#450000|085219781422|example@mail.com|http://192.168.1.212:5050/services/api/callback/cb.controller\n"
    }

    const endpointUrl = '/va/management/create'
    const externalId = crypto.randomUUID()
    const { signature, timestamp } = createHMACSignature('POST', endpointUrl, accessToken, requestBody)

    const headers = {
        'x-external-id': externalId,
        'x-timestamp': timestamp,
        'channel-id': CONFIG.clientId,
        'endpoint-url': endpointUrl,
        'x-partner-id': CONFIG.partnerId,
        'authorization': `Bearer ${accessToken}`,
        'host': CONFIG.host,
        'x-signature': signature,
        'Cache-Control': 'no-cache',
        'Accept-Encoding': 'gzip, deflate, br',
        'Content-Type': 'application/json',
    }

    console.log('VA Request Details:')
    console.log('- External ID:', externalId)
    console.log('- Endpoint:', endpointUrl)
    console.log('- Timestamp:', timestamp)

    // Note: URL mismatch between endpointUrl and actual URL - keeping as original
    const url = `${CONFIG.apiUrl}/services/va/management/create.controller`

    const response = await makeRequest(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(requestBody)
    })

    const data = await response.json()
    console.log('VA Response:', data)

    return data
}

/**
 * Main execution function
 */
async function main() {
    try {
        // Validate configuration
        validateConfig()

        console.log('🚀 Starting Virtual Account Service')
        console.log('Environment:', CONFIG.apiUrl)

        // Step 1: Get access token
        const accessToken = await createAccessToken()

        // Step 2: Create virtual account
        const result = await createVirtualAccount(accessToken)

        console.log('\n✅ Process completed successfully')
        console.log('Final Result:', JSON.stringify(result, null, 2))

        return result

    } catch (error) {
        console.error('\n❌ Process failed:', error.message)
        throw error
    }
}

// Export functions for module usage
export {
    createAccessToken,
    createVirtualAccount,
    createAuthSignature,
    createHMACSignature,
    getCurrentTimestamp,
    main
}

// Run main function if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch(error => {
        console.error('Unhandled error:', error)
        process.exit(1)
    })
}