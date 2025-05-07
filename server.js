const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

// Update CORS configuration
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
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

// Database connection setup - only establish if all DB vars are present
let db = null;
if (process.env.DB_HOST && process.env.DB_USER && 
    process.env.DB_PASSWORD && process.env.DB_NAME) {
    
    db = mysql.createConnection({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        connectTimeout: 10000,
    });
    
    // Test connection but don't crash on error
    db.connect((err) => {
        if (err) {
            console.error('Error connecting to the database:', err);
            db = null; // Reset db if connection fails
        } else {
            console.log('Connected to the MySQL database.');
        }
    });
}

// Telegram verification function
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
        
        const dataCheckString = Object.keys(data)
            .filter(key => key !== 'hash')
            .sort()
            .map(key => `${key}=${data[key]}`)
            .join('\n');
        
        const calculatedHash = crypto
            .createHmac('sha256', secretKey)
            .update(dataCheckString)
            .digest('hex');
        
        return calculatedHash === data.hash;
    } catch (error) {
        console.error('Error in verification:', error);
        return false;
    }
}

// Debug endpoint
app.get('/debug', (req, res) => {
    res.json({
        environment: {
            nodeEnv: process.env.NODE_ENV,
            hasToken: !!process.env.TELEGRAM_BOT_TOKEN,
            botTokenPrefix: process.env.TELEGRAM_BOT_TOKEN ? 
                process.env.TELEGRAM_BOT_TOKEN.substring(0, 5) + '...' : 'Not set',
            hasDbConfig: !!(process.env.DB_HOST && process.env.DB_USER && 
                process.env.DB_PASSWORD && process.env.DB_NAME),
            databaseConnected: !!db,
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

// Telegram auth endpoint
app.get('/api/telegram-auth', (req, res) => {
    console.log('Telegram auth request received');
    console.log('Query parameters:', req.query);
    
    const telegramData = req.query;
    
    try {
        // Basic validation
        if (!telegramData || !telegramData.id) {
            console.error('No Telegram data received');
            return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=no_data');
        }
        
        // Extract the data
        const { id, first_name, last_name, username, photo_url, auth_date, hash } = telegramData;
        const type = telegramData.type || 'Suiter';
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
        
        // Store in database if connection exists
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
                    [id, first_name, last_name, username, photo_url, authDate, type, badge],
                    (err) => {
                        if (err) {
                            console.error('Database error:', err);
                        } else {
                            console.log(`User ${id} authenticated successfully and stored in DB`);
                        }
                        // Always redirect to success even if DB operations fail
                        res.redirect('https://test.suitwalk-linz.at/#/anmeldung/erfolgreich');
                    }
                );
            } catch (dbError) {
                console.error('Database operation failed:', dbError);
                res.redirect('https://test.suitwalk-linz.at/#/anmeldung/erfolgreich');
            }
        } else {
            console.log('Database not connected, skipping data storage');
            res.redirect('https://test.suitwalk-linz.at/#/anmeldung/erfolgreich');
        }
    } catch (error) {
        console.error('General error:', error);
        res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=server_error');
    }
});

// Test endpoint for basic functionality verification
app.get('/test', (req, res) => {
    res.json({ message: 'Test endpoint working' });
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