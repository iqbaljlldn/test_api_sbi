import fs from 'fs'
import crypto from 'crypto'
import https from 'https'
import fetch from 'node-fetch'
import dotenv from 'dotenv'
dotenv.config()

const privateKey = fs.readFileSync('key', 'utf-8')
const clientId = process.env.CLIENT_ID || ''
const apiUrl = process.env.BASE_URL_DEVELOPMENT || ''
const externalId = crypto.randomUUID();
const clientSecret = process.env.CLIENT_SECRET || ''
const partnerId = process.env.PARTNER_ID || ''

function generateAuthSignature() {
    const timestamp = new Date().toISOString().replace("Z", "07:00")
    const data = `${clientId}|${timestamp}`
    const sign = crypto.createSign('SHA256')
    sign.update(data)
    sign.end()
    const signature = sign.sign(privateKey, 'base64')
    return { signature, timestamp }
}

function generateTransactionSignature(signatureEndpoint, accessToken, requestBody) {
    function generateBodySignature(body) {
        try {
            const minifiedBody = JSON.stringify(body);
            console.log('Body for signature:', minifiedBody);
            const hexHash = crypto.createHash('sha256').update(minifiedBody, 'utf8').digest('hex');
            return hexHash.toLowerCase();
        } catch (error) {
            console.error("Error processing request body:", error);
            return null;
        }
    }

    const timestamp = new Date().toISOString().replace("Z", "07:00")
    const bodySignature = generateBodySignature(requestBody);

    const data = `POST:${signatureEndpoint}:${accessToken}:${bodySignature}:${timestamp}`;

    console.log('Signature data string:', data);

    const hmac = crypto.createHmac('sha512', clientSecret);
    hmac.update(data, 'utf8');
    const signature = hmac.digest('base64');

    return { signature, timestamp };
}

async function auth() {
    const { signature, timestamp } = generateAuthSignature();

    console.log('Auth signature data:', `${clientId}|${timestamp}`); // Debug log

    const response = await fetch(`${apiUrl}/services/trx/auth.controller`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-TIMESTAMP': timestamp,
            'X-SIGNATURE': signature,
            'X-CLIENT-KEY': clientId,
        },
        body: JSON.stringify({
            "grantType": "client_credentials"
        }),
        agent: new https.Agent({
            rejectUnauthorized: false
        })
    });

    const data = await response.json();
    console.log('Auth Response:', data);

    if (data.accessToken) {
        console.log('Auth successful. Access Token:', data.accessToken);
        return data.accessToken;
    } else {
        throw new Error('Authentication failed: ' + JSON.stringify(data));
    }
}

async function inquiry(accessToken) {
    const fullEndpoint = "/services/trx/inquiry.controller";
    const signatureEndpoint = "/bank-account-inquiry";

    const requestBody = {
        "amount": {
            "currency": "IDR",
            "value": "20000.00"
        },
        "beneficiaryAccountNumber": "3010167428",
        "additionalInfo": {
            "switcher": ""
        },
        "partnerReferenceNo": "202411123-ACCTINQ-00012",
        "beneficiaryBankCode": "014"
    };

    const { signature, timestamp } = generateTransactionSignature(signatureEndpoint, accessToken, requestBody);

    console.log('Request headers:');
    console.log('X-TIMESTAMP:', timestamp);
    console.log('X-SIGNATURE:', signature);
    console.log('X-EXTERNAL-ID:', externalId);

    const response = await fetch(`${apiUrl}${fullEndpoint}`, {
        method: "POST",
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`,
            'X-TIMESTAMP': timestamp,
            'X-PARTNER-ID': `${partnerId}.${clientId}`,
            'X-SIGNATURE': signature,
            'X-EXTERNAL-ID': externalId,
            'CHANNEL-ID': clientId,
        },
        body: JSON.stringify(requestBody),
        agent: new https.Agent({
            rejectUnauthorized: false
        })
    });

    const data = await response.json();
    console.log('Inquiry Response:', data);
    return data;
}

async function transfer(accessToken) {
    const fullEndpoint = "/services/trx/transfer.controller";
    const signatureEndpoint = "/transfer-bank";

    const requestBody = {
        "beneficiaryAccountName": "JohnDoe",
        "beneficiaryEmail": "",
        "amount": {
            "currency": "IDR",
            "value": "0"
        },
        "beneficiaryAccountNumber": "8080800800",
        "beneficiaryBankName": "BSI",
        "additionalInfo": {
            "switcher": ""
        },
        "partnerReferenceNo": "2020102900000000001",
        "beneficiaryBankCode": "451"
    }

    const { signature, timestamp } = generateTransactionSignature(signatureEndpoint, accessToken, requestBody)

    console.log('Request headers:');
    console.log('X-TIMESTAMP:', timestamp);
    console.log('X-SIGNATURE:', signature);
    console.log('X-EXTERNAL-ID:', externalId);

    const response = await fetch(`${apiUrl}${fullEndpoint}`, {
        method: "POST",
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`,
            'X-TIMESTAMP': timestamp,
            'X-PARTNER-ID': `${partnerId}.${clientId}`,
            'X-SIGNATURE': signature,
            'X-EXTERNAL-ID': externalId,
            'CHANNEL-ID': clientId,
        },
        body: JSON.stringify(requestBody),
        agent: new https.Agent({
            rejectUnauthorized: false
        })
    });

    const data = await response.json();
    console.log('Inquiry Response:', data);
    return data;
}

async function transferInquiry(accessToken, externalId) {
    const fullEndpoint = "/services/trx/transferInquiry.controller";
    const signatureEndpoint = "/transfer-status";

    const requestBody = {
        "originalExternalId": "24264916",
        "partnerReferenceNo ":
            "2024111114223423001",
        "serviceCode ": "18"
    }

    const { signature, timestamp } = generateTransactionSignature(signatureEndpoint, accessToken, requestBody)

    console.log('Request headers:');
    console.log('X-TIMESTAMP:', timestamp);
    console.log('X-SIGNATURE:', signature);
    console.log('X-EXTERNAL-ID:', externalId);

    const response = await fetch(`${apiUrl}${fullEndpoint}`, {
        method: "POST",
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`,
            'X-TIMESTAMP': timestamp,
            'X-PARTNER-ID': `${partnerId}.${clientId}`,
            'X-SIGNATURE': signature,
            'X-EXTERNAL-ID': externalId,
            'CHANNEL-ID': clientId,
        },
        body: JSON.stringify(requestBody),
        agent: new https.Agent({
            rejectUnauthorized: false
        })
    });

    const data = await response.json();
    console.log('Inquiry Response:', data);
    return data;
}

auth()
    .then(accessToken => inquiry(accessToken))
    .catch(error => console.error('An error occurred:', error));

auth()
    .then(accessToken => transfer(accessToken))
    .catch(error => console.error('An error occurred:', error))

auth()
    .then(accessToken => transferInquiry(accessToken, externalId))
    .catch(error => console.error('An error occurred:', error))