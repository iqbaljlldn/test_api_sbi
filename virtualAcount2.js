import crypto from 'crypto';
import https from 'https';
import http from 'http';
import fs from 'fs'
import dotenv from 'dotenv'

dotenv.config()

const baseUrl = process.env.BASE_URL_DEVELOPMENT || '';
const clientKey = process.env.CLIENT_ID || '';
const partnerId = process.env.PARTNER_ID || '';
const clientSecret = process.env.CLIENT_SECRET;
const privateKey = fs.readFileSync('key', 'utf-8')

class VAAPITester {
    constructor(baseURL, clientKey, partnerId, clientSecret, privateKey) {
        // Configuration
        this.baseURL = baseURL; // Development URL
        this.clientKey = clientKey;
        this.partnerId = partnerId;
        this.clientSecret = clientSecret; // Ganti dengan client secret yang sebenarnya
        this.privateKey = privateKey; // Ganti dengan private key yang sebenarnya

        this.accessToken = null;
        this.externalId = '123';
    }

    // Utility: Generate timestamp
    generateTimestamp() {
        const now = new Date()
        const pad = n => n.toString().padStart(2, '0')

        return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}T${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}+07:00`
    }

    // Utility: Generate signature untuk Create Token
    generateAuthSignature(timestamp) {
        const stringToSign = `${this.clientKey}|${timestamp}`;
        const signature = crypto.sign('sha256', Buffer.from(stringToSign), this.privateKey);
        return signature.toString('base64');
    }

    // Utility: Generate signature untuk endpoint lain
    generateSignature(method, endpoint, accessToken, requestBody, timestamp) {
        const hashedBody = crypto.createHash('sha256')
            .update(JSON.stringify(requestBody).replace(/\s/g, ''))
            .digest('hex')
            .toLowerCase();

        const stringToProcess = `${method}:${endpoint}:${accessToken}:${hashedBody}:${timestamp}`;

        const signature = crypto.createHmac('sha512', this.clientSecret)
            .update(stringToProcess)
            .digest('base64');

        return signature;
    }

    // Utility: HTTP Request
    makeRequest(options, data = null) {
        return new Promise((resolve, reject) => {
            const protocol = options.hostname.includes('https') || options.port === 443 ? https : http;

            if (protocol === https) {
                options.agent = new https.Agent({
                    rejectUnauthorized: false
                });
            }

            const req = protocol.request(options, (res) => {
                let body = '';

                res.on('data', (chunk) => {
                    body += chunk;
                });

                res.on('end', () => {
                    try {
                        const response = JSON.parse(body);
                        resolve({
                            statusCode: res.statusCode,
                            headers: res.headers,
                            data: response
                        });
                    } catch (error) {
                        resolve({
                            statusCode: res.statusCode,
                            headers: res.headers,
                            data: body
                        });
                    }
                });
            });

            req.on('error', (error) => {
                reject(error);
            });

            if (data) {
                req.write(JSON.stringify(data));
            }

            req.end();
        });
    }

    // 1. Create Access Token
    async createAccessToken() {
        console.log('\n=== Testing Create Access Token ===');

        const timestamp = this.generateTimestamp();
        const signature = this.generateAuthSignature(timestamp);

        const options = {
            hostname: '103.214.54.198',
            port: 443,
            path: '/services/va/management/auth.controller',
            method: 'POST',
            headers: {
                'x-client-key': this.clientKey,
                'x-timestamp': timestamp,
                'x-signature': signature,
                'Content-Type': 'application/json; charset=UTF-8'
            }
        };

        const requestBody = {
            grantType: 'client_credentials'
        };

        try {
            const response = await this.makeRequest(options, requestBody);
            console.log('Status Code:', response.statusCode);
            console.log('Response:', JSON.stringify(response.data, null, 2));

            if (response.data.accessToken) {
                this.accessToken = response.data.accessToken;
                console.log('✅ Access Token berhasil didapat!');
                return true;
            } else {
                console.log('❌ Gagal mendapat Access Token');
                return false;
            }
        } catch (error) {
            console.error('❌ Error:', error.message);
            return false;
        }
    }

    // 2. Create VA
    async createVA() {
        console.log('\n=== Testing Create VA ===');

        if (!this.accessToken) {
            console.log('❌ Access Token tidak tersedia');
            return false;
        }

        const timestamp = this.generateTimestamp();
        const endpoint = '/services/va/management/create.controller';

        const requestBody = {
            dataVa: "2310140002|MUHAMMAD AZRIL AL QURTHUBI|900000|2|SPP 1124#450000!SPP 1224#450000|085219781422|example@mail.com\n2313080596|PIKRI HAIKAL MUBAROK|450000|1|SPP 1224#450000|085219781422|example@mail.com|http://192.168.1.212:5050/services/api/callback/cb.controller \n"
        };

        const signature = this.generateSignature('POST', endpoint, this.accessToken, requestBody, timestamp);

        const options = {
            hostname: '103.214.54.198',
            port: 443,
            path: endpoint,
            method: 'POST',
            headers: {
                'Accept': '*/*',
                'x-external-id': this.externalId,
                'x-timestamp': timestamp,
                'channel-id': this.clientKey,
                'endpoint-url': '/va/management/create',
                'x-partner-id': this.partnerId,
                'authorization': `Bearer ${this.accessToken}`,
                'host': '103.214.54.198',
                'x-signature': signature,
                'Cache-Control': 'no-cache',
                'Accept-Encoding': 'gzip, deflate, br',
                'Content-Type': 'application/json; charset=UTF-8'
            }
        };

        try {
            console.log('Access Token:',this.accessToken)
            console.log('Signature:', signature)
            console.log('Endpoint untuk header:', '/va/management/create')
            console.log('Endpoint URL:', endpoint)
            const response = await this.makeRequest(options, requestBody);
            console.log('Status Code:', response.statusCode);
            console.log('Response:', JSON.stringify(response.data, null, 2));

            if (response.data.responseCode === '2002400') {
                console.log('✅ VA berhasil dibuat!');
                return response.data.dataVa;
            } else {
                console.log('❌ Gagal membuat VA');
                return null;
            }
        } catch (error) {
            console.error('❌ Error:', error.message);
            return null;
        }
    }

    // 3. Inquiry Status VA
    async inquiryStatusVA(vaNumbers) {
        console.log('\n=== Testing Inquiry Status VA ===');

        if (!this.accessToken) {
            console.log('❌ Access Token tidak tersedia');
            return false;
        }

        const timestamp = this.generateTimestamp();
        const endpoint = '/va/management/checkStatus';

        const requestBody = {
            dataVa: Array.isArray(vaNumbers) ? vaNumbers.join('|') : vaNumbers
        };

        const signature = this.generateSignature('POST', endpoint, this.accessToken, requestBody, timestamp);

        const options = {
            hostname: '103.214.54.198',
            port: 443,
            path: '/services/va/management/checkStatus.controller',
            method: 'POST',
            headers: {
                'Accept': '*/*',
                'x-external-id': this.externalId,
                'x-timestamp': timestamp,
                'channel-id': this.clientKey,
                'endpoint-url': endpoint,
                'x-partner-id': this.partnerId,
                'authorization': `Bearer ${this.accessToken}`,
                'host': '103.214.54.198',
                'x-signature': signature,
                'Cache-Control': 'no-cache',
                'Accept-Encoding': 'gzip, deflate, br',
                'Content-Type': 'application/json; charset=UTF-8'
            }
        };

        try {
            const response = await this.makeRequest(options, requestBody);
            console.log('Status Code:', response.statusCode);
            console.log('Response:', JSON.stringify(response.data, null, 2));

            if (response.data.responseCode === '2002400') {
                console.log('✅ Inquiry status berhasil!');
                return response.data.dataVa;
            } else {
                console.log('❌ Gagal inquiry status');
                return null;
            }
        } catch (error) {
            console.error('❌ Error:', error.message);
            return null;
        }
    }

    // 4. Reject Status VA
    async rejectStatusVA(vaNumber) {
        console.log('\n=== Testing Reject Status VA ===');

        if (!this.accessToken) {
            console.log('❌ Access Token tidak tersedia');
            return false;
        }

        const timestamp = this.generateTimestamp();
        const endpoint = '/va/management/updateStatusVa';

        const requestBody = {
            dataVa: `${vaNumber}#reject`
        };

        const signature = this.generateSignature('POST', endpoint, this.accessToken, requestBody, timestamp);

        const options = {
            hostname: '103.214.54.198',
            port: 443,
            path: '/services/va/management/updateStatusVa.controller',
            method: 'POST',
            headers: {
                'Accept': '*/*',
                'x-external-id': this.externalId,
                'x-timestamp': timestamp,
                'channel-id': this.clientKey,
                'endpoint-url': endpoint,
                'x-partner-id': this.partnerId,
                'authorization': `Bearer ${this.accessToken}`,
                'host': '103.214.54.198',
                'x-signature': signature,
                'Cache-Control': 'no-cache',
                'Accept-Encoding': 'gzip, deflate, br',
                'Content-Type': 'application/json; charset=UTF-8'
            }
        };

        try {
            const response = await this.makeRequest(options, requestBody);
            console.log('Status Code:', response.statusCode);
            console.log('Response:', JSON.stringify(response.data, null, 2));

            if (response.data.responseCode === 2002400) {
                console.log('✅ Reject status berhasil!');
                return true;
            } else {
                console.log('❌ Gagal reject status');
                return false;
            }
        } catch (error) {
            console.error('❌ Error:', error.message);
            return false;
        }
    }

    // Run all tests
    async runAllTests() {
        console.log('🚀 Memulai Testing API VA...');
        console.log('Base URL:', this.baseURL);

        try {
            // 1. Create Access Token
            const tokenSuccess = await this.createAccessToken();
            if (!tokenSuccess) {
                console.log('❌ Testing dihentikan karena gagal mendapat access token');
                return;
            }

            // 2. Create VA
            const createdVAs = await this.createVA();
            if (!createdVAs || createdVAs.length === 0) {
                console.log('❌ Testing dihentikan karena gagal membuat VA');
                return;
            }

            // Extract VA numbers for further testing
            const vaNumbers = createdVAs.map(va => va.noVa);
            console.log('VA Numbers untuk testing:', vaNumbers);

            // 3. Inquiry Status VA
            await this.inquiryStatusVA(vaNumbers);

            // 4. Reject Status VA (testing dengan VA pertama)
            if (vaNumbers.length > 0) {
                await this.rejectStatusVA(vaNumbers[0]);
            }

            console.log('\n🎉 Semua testing selesai!');

        } catch (error) {
            console.error('❌ Error dalam menjalankan testing:', error.message);
        }
    }
}

// Jalankan testing
async function main() {
    console.log('========================================');
    console.log('       VA API TESTING TOOL');
    console.log('========================================');

    const tester = new VAAPITester(baseUrl, clientKey, partnerId, clientSecret, privateKey);

    // Peringatan untuk konfigurasi
    console.log('⚠️  PENTING: Pastikan untuk mengganti nilai berikut di code:');
    console.log('   - clientSecret: CLIENT_SECRET yang sebenarnya');
    console.log('   - privateKey: PRIVATE_KEY yang sebenarnya');
    console.log(`   - ${baseUrl}`)
    console.log(`   - ${clientKey}`);
    console.log('');

    await tester.runAllTests();
}

// Eksekusi testing
main().catch(console.error);