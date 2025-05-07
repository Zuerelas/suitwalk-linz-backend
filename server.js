const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

// Add CORS headers
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "https://test.suitwalk-linz.at");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
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

// Verify Telegram Authentication
function verifyTelegramAuth(data) {
    const token = process.env.TELEGRAM_BOT_TOKEN;
    const secretKey = crypto.createHash('sha256').update(token).digest();
    const dataCheckString = Object.keys(data)
        .filter((key) => key !== 'hash')
        .sort()
        .map((key) => `${key}=${data[key]}`)
        .join('\n');
    const hash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
    return hash === data.hash;
}

// Change the root handler to handle telegram-auth specifically
app.get('/api/telegram-auth', (req, res) => {
    console.log('Telegram auth request received');
    console.log('Query parameters:', req.query);
    
    const telegramData = req.query;
    
    if (!telegramData || !telegramData.id) {
        console.error('No Telegram data received');
        return res.status(400).send('Bad request: No Telegram data received');
    }
    
    console.log('Received Telegram data:', telegramData);
    
    // Extract the standard Telegram data
    const { id, first_name, last_name, username, photo_url, auth_date, hash } = telegramData;
    
    // Extract custom parameters if they exist, or use defaults
    const type = telegramData.type || 'Visitor';
    const badge = telegramData.badge === 'true' || false;

    try {
        // Verify Telegram data
        if (!verifyTelegramAuth(telegramData)) {
            console.error('Invalid Telegram authentication data:', telegramData);
            return res.status(401).send('Unauthorized: Invalid Telegram data.');
        }

        // Validate auth_date to prevent replay attacks
        const authDate = parseInt(telegramData.auth_date, 10);
        const currentTime = Math.floor(Date.now() / 1000); // Current time in seconds
        if (currentTime - authDate > 86400) { // Allow a maximum of 24 hours
            console.error('Authentication data is too old:', telegramData);
            return res.status(401).send('Unauthorized: Authentication data is too old.');
        }

        // Insert or update user in the database
        console.log('Query values:', { id, first_name, last_name, username, photo_url, authDate, type, badge });
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
                    console.error('Error inserting/updating user:', err.message, err);
                    return res.status(500).send('Internal Server Error');
                }

                console.log(`User ${id} successfully authenticated and stored.`);
                // Redirect to success page
                res.redirect(`https://test.suitwalk-linz.at/#/anmeldung/erfolgreich`);
            }
        );
    } catch (error) {
        console.error('Error processing request:', error);
        return res.status(500).send('Server error processing the request');
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