const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

// Update your CORS configuration
app.use((req, res, next) => {
    // Allow requests from both your test domain and Telegram
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    next();
});

// Validate required environment variables
const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'TELEGRAM_BOT_TOKEN', 'PORT'];
requiredEnvVars.forEach((envVar) => {
    if (!process.env[envVar]) {
        console.error(`Missing required environment variable: ${envVar}`);
        process.exit(1);
    }
});

// MySQL Database Connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    connectTimeout: 10000, // 10 seconds
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to the database:', err);
        process.exit(1);
    }
    console.log('Connected to the MySQL database.');
});

// Fix your verifyTelegramAuth function
function verifyTelegramAuth(data) {
    if (!data || !data.hash) {
        console.error('Missing hash in data');
        return false;
    }
    
    try {
        const token = process.env.TELEGRAM_BOT_TOKEN;
        const secretKey = crypto.createHash('sha256').update(token).digest();
        
        // Create the data check string exactly as Telegram does
        const dataCheckString = Object.keys(data)
            .filter(key => key !== 'hash')
            .sort()
            .map(key => `${key}=${data[key]}`)
            .join('\n');
            
        console.log('Data check string:', dataCheckString);
        
        // Calculate the hash
        const calculatedHash = crypto
            .createHmac('sha256', secretKey)
            .update(dataCheckString)
            .digest('hex');
            
        console.log('Calculated hash:', calculatedHash);
        console.log('Provided hash:', data.hash);
        
        return calculatedHash === data.hash;
    } catch (error) {
        console.error('Error in verification:', error);
        return false;
    }
}

// Add a debug endpoint
app.get('/debug', (req, res) => {
    res.json({
        environment: {
            nodeEnv: process.env.NODE_ENV,
            hasToken: !!process.env.TELEGRAM_BOT_TOKEN,
            botTokenPrefix: process.env.TELEGRAM_BOT_TOKEN ? 
                process.env.TELEGRAM_BOT_TOKEN.substring(0, 5) + '...' : 'Not set',
            hasDbConfig: !!(process.env.DB_HOST && process.env.DB_USER && 
                process.env.DB_PASSWORD && process.env.DB_NAME),
        },
        timestamp: new Date().toISOString()
    });
});

// Add proper handling for OPTIONS requests for CORS
app.options('*', (req, res) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.sendStatus(200);
});

// Update the telegram auth endpoint
app.get('/api/telegram-auth', (req, res) => {
    console.log('Telegram auth request received');
    console.log('Query parameters:', req.query);
    
    const telegramData = req.query;
    
    // Handle validation, authentication and redirect in separate try-catch blocks
    try {
        // Basic validation
        if (!telegramData || !telegramData.id) {
            console.error('No Telegram data received');
            return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=no_data');
        }
        
        // Extract the data
        const { id, first_name, last_name, username, photo_url, auth_date, hash } = telegramData;
        const type = telegramData.type || 'Suiter';  // Default to Suiter
        const badge = telegramData.badge === 'true' || false;
        
        // Verify the data
        if (!verifyTelegramAuth(telegramData)) {
            console.error('Invalid Telegram authentication data');
            return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=invalid_auth');
        }
        
        // Validate auth_date
        const authDate = parseInt(auth_date, 10);
        const currentTime = Math.floor(Date.now() / 1000);
        if (currentTime - authDate > 86400) {
            console.error('Authentication data is too old');
            return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=auth_expired');
        }
        
        // Store in database (wrapped in try-catch to prevent crashing)
        try {
            const query = `
                INSERT INTO users (telegram_id, first_name, last_name, username, photo_url, auth_date, type, badge)
                VALUES (?, ?, ?, ?, ?, FROM_UNIXTIME(?), ?, ?)
                ON DUPLICATE KEY UPDATE
                first_name = VALUES(first_name),
                last_name = VALUES(last_name),
                username = VALUES(username),
                photo_url = VALUES(photo_url),
                auth_date = VALUES(auth_date),
                type = VALUES(type),
                badge = VALUES(badge);
            `;
            
            db.query(
                query,
                [id, first_name, last_name, username, photo_url, authDate, type, badge],
                (err) => {
                    if (err) {
                        console.error('Database error:', err);
                        // Continue with redirect even if DB fails
                    }
                    
                    console.log(`User ${id} authenticated successfully`);
                    // Redirect to success page
                    res.redirect('https://test.suitwalk-linz.at/#/anmeldung/erfolgreich');
                }
            );
        } catch (dbError) {
            console.error('Database operation failed:', dbError);
            // Still redirect to success if DB fails but auth was valid
            res.redirect('https://test.suitwalk-linz.at/#/anmeldung/erfolgreich');
        }
    } catch (error) {
        console.error('General error:', error);
        res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=server_error');
    }
});

// Keep a root handler for health checks
app.get('/', (req, res) => {
    res.send('API server is running');
});

// Start the Server
const PORT = process.env.PORT || 3306;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});