const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

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

// Telegram Auth Endpoint
app.get('/api/telegram-auth', (req, res) => {
    const telegramData = req.query;

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
    const { id, first_name, last_name, username, photo_url } = telegramData;
    const query = `
        INSERT INTO users (telegram_id, first_name, last_name, username, photo_url, auth_date)
        VALUES (?, ?, ?, ?, ?, FROM_UNIXTIME(?))
        ON DUPLICATE KEY UPDATE
        first_name = VALUES(first_name),
        last_name = VALUES(last_name),
        username = VALUES(username),
        photo_url = VALUES(photo_url),
        auth_date = VALUES(auth_date);
    `;

    db.query(
        query,
        [id, first_name, last_name, username, photo_url, authDate],
        (err) => {
            if (err) {
                console.error('Error inserting/updating user:', err);
                return res.status(500).send('Internal Server Error');
            }

            console.log(`User ${id} successfully authenticated and stored.`);
            // Redirect to success page
            res.redirect(`https://test.suitwalk-linz.at/anmeldung/erfolgreich`);
        }
    );
});

// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});