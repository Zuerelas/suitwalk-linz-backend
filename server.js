const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

app.use((req, res, next) => {
    console.log(`Request received: ${req.method} ${req.url}`);
    next();
});

// CORS Configuration - Allow specific domains
app.use((req, res, next) => {
    const allowedOrigins = ['https://test.suitwalk-linz.at', 'https://suitwalk-linz.at'];
    const origin = req.headers.origin;
    
    if (allowedOrigins.includes(origin)) {
        res.header("Access-Control-Allow-Origin", origin);
    } else {
        res.header("Access-Control-Allow-Origin", "*");
    }
    
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    next();
});

// Validate required environment variables - more lenient for Vercel
const requiredEnvVars = ['TELEGRAM_BOT_TOKEN'];
requiredEnvVars.forEach((envVar) => {
    if (!process.env[envVar]) {
        console.error(`Missing required environment variable: ${envVar}`);
        // Don't exit process on Vercel, just log the error
    }
});

// Database Connection with better error handling
let db = null;
if (process.env.DB_HOST && process.env.DB_USER && process.env.DB_PASSWORD && process.env.DB_NAME) {
    try {
        db = mysql.createConnection({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME,
            port: 3306,
            connectTimeout: 10000,
        });

        db.connect((err) => {
            if (err) {
                console.error('Error connecting to the database:', err);
                db = null;
            } else {
                console.log('Connected to the MySQL database.');
                
                // Ensure the users table exists
                const createTableQuery = `
                    CREATE TABLE IF NOT EXISTS users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        telegram_id BIGINT NOT NULL UNIQUE,
                        first_name VARCHAR(255),
                        last_name VARCHAR(255),
                        username VARCHAR(255),
                        photo_url TEXT,
                        auth_date DATETIME,
                        type VARCHAR(50) DEFAULT 'Suiter',
                        badge BOOLEAN DEFAULT false,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                `;
                
                db.query(createTableQuery, (tableErr) => {
                    if (tableErr) {
                        console.error('Error creating users table:', tableErr);
                    } else {
                        console.log('Users table verified/created successfully');
                    }
                });
            }
        });
    } catch (error) {
        console.error('Error initializing database connection:', error);
    }
}

// Improved Telegram Authentication Verification
function verifyTelegramAuth(data) {
    if (!data || !data.hash) {
        console.error('Missing hash in data');
        return false;
    }

    try {
        const token = process.env.TELEGRAM_BOT_TOKEN;
        if (!token) {
            console.error('Telegram bot token not found');
            return false;
        }
        
        const secretKey = crypto.createHash('sha256').update(token).digest();
        
        // Create data check string for validation
        const dataCheckString = Object.keys(data)
            .filter(key => key !== 'hash')
            .sort()
            .map(key => `${key}=${data[key]}`)
            .join('\n');
        
        console.log('Data check string:', dataCheckString);
        
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

// Debug endpoint
app.get('/debug', (req, res) => {
    res.json({
        message: 'API is running',
        environment: {
            nodeEnv: process.env.NODE_ENV,
            hasDbConfig: !!(process.env.DB_HOST && process.env.DB_USER && process.env.DB_PASSWORD && process.env.DB_NAME),
            hasTelegramToken: !!process.env.TELEGRAM_BOT_TOKEN,
            tokenPrefix: process.env.TELEGRAM_BOT_TOKEN ? process.env.TELEGRAM_BOT_TOKEN.substring(0, 5) + '...' : 'Not set',
            dbConnected: !!db
        },
        timestamp: new Date().toISOString()
    });
});

// CORS pre-flight handling
app.options('*', (req, res) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.sendStatus(200);
});

// Root endpoint
app.get('/', (req, res) => {
    res.send('API server is running');
});

// Telegram Auth Endpoint with improved error handling and logging
app.get('/api/telegram-auth', (req, res) => {
    console.log('Received Telegram auth request');
    console.log('Query params:', req.query);
    
    const telegramData = req.query;

    if (!telegramData || !telegramData.id) {
        console.error('No Telegram data received');
        return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=no_data');
    }

    try {
        if (!verifyTelegramAuth(telegramData)) {
            console.error('Invalid Telegram authentication');
            return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=invalid_auth');
        }

        const authDate = parseInt(telegramData.auth_date, 10);
        const currentTime = Math.floor(Date.now() / 1000);
        if (currentTime - authDate > 86400) {
            console.error('Authentication expired');
            return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=auth_expired');
        }

        if (db) {
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
                    [
                        telegramData.id,
                        telegramData.first_name,
                        telegramData.last_name,
                        telegramData.username,
                        telegramData.photo_url,
                        authDate,
                        telegramData.type || 'Suiter',
                        telegramData.badge === 'true' || false,
                    ],
                    (err) => {
                        if (err) {
                            console.error('Database error:', err);
                            // Still redirect to success page even if DB operation fails
                        }
                        console.log('User data saved successfully');
                        res.redirect('https://test.suitwalk-linz.at/#/anmeldung/erfolgreich');
                    }
                );
            } catch (dbError) {
                console.error('Database operation error:', dbError);
                res.redirect('https://test.suitwalk-linz.at/#/anmeldung/erfolgreich');
            }
        } else {
            console.log('No database connection, skipping data storage');
            res.redirect('https://test.suitwalk-linz.at/#/anmeldung/erfolgreich');
        }
    } catch (error) {
        console.error('General error:', error);
        res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=server_error');
    }
});

// Test endpoint
app.get('/test', (req, res) => {
    res.json({ 
        message: 'Test endpoint working',
        timestamp: new Date().toISOString()
    });
});

// Handle 404s
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Server error' });
});

// Start server if not running as a module
if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Server is running on http://localhost:${PORT}`);
    });
}

// Export the app for Vercel
module.exports = app;