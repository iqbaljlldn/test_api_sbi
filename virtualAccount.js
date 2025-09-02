import fs from 'fs'
import crypto from 'crypto'
import https from 'https'
import fetch from 'node-fetch'
import dotenv from 'dotenv'
dotenv.config()

const privateKey = fs.readFileSync('key', 'utf-8')
const clientId = process.env.CLIENT_ID || ''
const apiUrl = process.env.BASE_URL_PRODUCTION || ''
const externalId = crypto.randomUUID();
const clientSecret = process.env.CLIENT_SECRET || ''
const partnerId = process.env.PARTNER_ID || ''

function createSignature() {
    // const timestamp = new Date().toISOString().replace("Z", "+07:00")
    const now = new Date()
    // format yyyy-MM-ddTHH:mm:ss
    const pad = n => n.toString().padStart(2, '0')
    const timestamp =
        now.getFullYear() + "-" +
        pad(now.getMonth() + 1) + "-" +
        pad(now.getDate()) + "T" +
        pad(now.getHours()) + ":" +
        pad(now.getMinutes()) + ":" +
        pad(now.getSeconds())

    const data = `${clientId}|${timestamp}`
    const sign = crypto.createSign('SHA256')
    sign.update(data)
    sign.end()
    const signature = sign.sign(privateKey, 'base64')
    return { signature, timestamp }
}

async function createToken() {
    const { signature, timestamp } = createSignature()

    const res = await fetch(`${apiUrl}/services/va/management/auth.controller`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'x-timestamp': timestamp,
            'x-signature': signature,
            'x-client-key': clientId,
        },
        body: JSON.stringify({
            "grantType": "client_credentials"
        }),
        agent: new https.Agent({
            rejectUnauthorized: false
        })
    });

    const data = await res.json();
    console.log('Auth Response:', data);

    if (data.accessToken) {
        console.log('Auth successful. Access Token:', data.accessToken);
        return data.accessToken;
    } else {
        throw new Error('Authentication failed: ' + JSON.stringify(data));
    }
}

createToken()