const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

// Then include your router and other middleware
const router = require('./router');
console.log('Router module loaded');
app.use('/api/router', router); // Change the mount path to avoid conflicts
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

// Database Connection with improved connection pooling
let db = null;
if (process.env.DB_HOST && process.env.DB_USER && process.env.DB_PASSWORD && process.env.DB_NAME) {
    try {
        db = mysql.createPool({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME,
            port: 3306,
            waitForConnections: true,
            connectionLimit: 5,
            queueLimit: 0,
            enableKeepAlive: true,
            keepAliveInitialDelay: 10000,
            connectTimeout: 30000,
            ssl: process.env.DB_SSL === 'true' ? true : undefined
        });
        
        console.log('Database pool created with configuration:', {
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            database: process.env.DB_NAME,
            port: 3306,
            ssl: process.env.DB_SSL === 'true' ? true : undefined
        });
        
        // Test the connection immediately
        db.getConnection((err, connection) => {
            if (err) {
                console.error('Error connecting to the database:', err);
                console.error('Connection error details:', {
                    code: err.code,
                    errno: err.errno,
                    sqlState: err.sqlState,
                    sqlMessage: err.sqlMessage
                });
                // Don't set db to null, just log the error
            } else {
                console.log('Connected to the MySQL database successfully');
                connection.release(); // Release the connection back to the pool
                
                // Ensure the users table exists
                db.query(`
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
                `, (tableErr) => {
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
} else {
    console.error('Database configuration missing. Required environment variables: DB_HOST, DB_USER, DB_PASSWORD, DB_NAME');
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
        
        // Create data check string for validation - exclude custom parameters
        const dataCheckString = Object.keys(data)
            .filter(key => key !== 'hash' && !key.startsWith('custom_'))
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
    
    // Read custom parameters from the query string
    const customType = req.query.custom_type;
    const customBadge = req.query.custom_badge;
    
    console.log('Custom badge value:', customBadge);
    console.log('Custom type value:', customType);
    
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

        // Check if database is available
        if (!db) {
            console.error('Database connection is not available');
            return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=database_error');
        }

        // Test database connection before proceeding
        db.getConnection((connErr, connection) => {
            if (connErr) {
                console.error('Failed to get database connection:', connErr);
                return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=database_error');
            }
            
            connection.release(); // Release the connection immediately
            
            // If this is a badge sign-up, first check if the user exists
            if (customBadge === 'true') {
                const checkUserQuery = `SELECT * FROM users WHERE telegram_id = ?`;
                
                db.query(checkUserQuery, [telegramData.id], (checkErr, results) => {
                    if (checkErr) {
                        console.error('Error checking user existence:', checkErr);
                        return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=database_error');
                    }
                    
                    // If user doesn't exist, redirect to error
                    if (results.length === 0) {
                        console.error('User tried to order badge but is not registered');
                        return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=register_first');
                    }
                    
                    // User exists, update only badge status
                    const updateQuery = `
                        UPDATE users 
                        SET badge = 1,
                            first_name = ?,
                            last_name = ?,
                            username = ?,
                            photo_url = ?,
                            auth_date = FROM_UNIXTIME(?)
                        WHERE telegram_id = ?
                    `;
                    
                    db.query(
                        updateQuery,
                        [
                            telegramData.first_name,
                            telegramData.last_name || '',
                            telegramData.username || '',
                            telegramData.photo_url || '',
                            authDate,
                            telegramData.id
                        ],
                        (updateErr) => {
                            if (updateErr) {
                                console.error('Database update error:', updateErr);
                                return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=database_error');
                            }
                            
                            console.log('Badge status updated successfully');
                            return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/erfolgreich');
                        }
                    );
                });
            } else {
                // Normal registration, insert or update user
                const query = `
                    INSERT INTO users (telegram_id, first_name, last_name, username, photo_url, auth_date, type, badge)
                    VALUES (?, ?, ?, ?, ?, FROM_UNIXTIME(?), ?, ?)
                    ON DUPLICATE KEY UPDATE
                    first_name = VALUES(first_name),
                    last_name = VALUES(last_name),
                    username = VALUES(username),
                    photo_url = VALUES(photo_url),
                    auth_date = VALUES(auth_date),
                    type = VALUES(type);
                `;

                db.query(
                    query,
                    [
                        telegramData.id,
                        telegramData.first_name,
                        telegramData.last_name || '',
                        telegramData.username || '',
                        telegramData.photo_url || '',
                        authDate,
                        customType || 'Suiter',
                        0  // Default badge to 0 for normal registrations
                    ],
                    (err) => {
                        if (err) {
                            console.error('Database query error:', err);
                            return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=database_error');
                        }
                        
                        console.log('User data saved successfully');
                        return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/erfolgreich');
                    }
                );
            }
        });
    } catch (error) {
        console.error('General error:', error);
        return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=server_error');
    }
});

// Test endpoint
app.get('/test', (req, res) => {
    res.json({ 
        message: 'Test endpoint working',
        timestamp: new Date().toISOString()
    });
});

app.post('/api/order-badge', (req, res) => {
    const { telegram_id } = req.body;

    if (!telegram_id) {
        return res.status(400).json({ message: 'Telegram ID is required' });
    }

    const query = `
        UPDATE users
        SET badge = 1
        WHERE telegram_id = ${db.escape(telegram_id)};
    `;

    db.query(query, (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ message: 'Database error' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({ message: 'Badge ordered successfully' });
    });
});

// Add a secure endpoint to get registration data
app.get('/api/registrations', (req, res) => {
    // Basic API key authentication
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || apiKey !== process.env.ADMIN_API_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!db) {
        return res.status(500).json({ error: 'Database connection not available' });
    }

    // Query to get all users with counts
    const query = `
        SELECT 
            type,
            COUNT(*) as count,
            SUM(CASE WHEN badge = 1 THEN 1 ELSE 0 END) as badge_count
        FROM users
        GROUP BY type
        ORDER BY count DESC;
    `;

    // Query to get detailed user data
    const detailedQuery = `
        SELECT 
            telegram_id, 
            first_name, 
            last_name, 
            username, 
            photo_url, 
            auth_date, 
            type, 
            badge,
            created_at
        FROM users
        ORDER BY created_at DESC;
    `;

    // Execute both queries
    db.query(query, (err, summaryResults) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        db.query(detailedQuery, (detailErr, detailResults) => {
            if (detailErr) {
                console.error('Database query error:', detailErr);
                return res.status(500).json({ error: 'Database error' });
            }

            // Calculate totals
            const totalUsers = detailResults.length;
            const totalBadges = detailResults.reduce((sum, user) => sum + (user.badge ? 1 : 0), 0);

            res.json({
                summary: summaryResults,
                details: detailResults,
                totals: {
                    users: totalUsers,
                    badges: totalBadges
                }
            });
        });
    });
});

// Public statistics endpoint - no authentication required
app.get('/api/public-stats', (req, res) => {
    console.log('Received request for public stats');
    
    if (!db) {
        console.error('Database connection not available for public stats');
        return res.status(500).json({ error: 'Database connection not available' });
    }

    // Query to get counts by type
    const query = `
        SELECT 
            type,
            COUNT(*) as count,
            SUM(CASE WHEN badge = 1 THEN 1 ELSE 0 END) as badge_count
        FROM users
        GROUP BY type
        ORDER BY count DESC;
    `;

    // Execute query
    db.query(query, (err, summaryResults) => {
        if (err) {
            console.error('Database query error in public-stats:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        // Get total counts without detailed user info
        const totalQuery = `
            SELECT 
                COUNT(*) as total_users,
                SUM(CASE WHEN badge = 1 THEN 1 ELSE 0 END) as total_badges
            FROM users;
        `;

        db.query(totalQuery, (totalErr, totalResults) => {
            if (totalErr) {
                console.error('Database query error in public-stats totals:', totalErr);
                return res.status(500).json({ error: 'Database error' });
            }

            // Query for attendee list (names only, no personal data)
            const attendeeQuery = `
                SELECT 
                    first_name,
                    type,
                    badge
                FROM users
                ORDER BY created_at DESC;
            `;

            db.query(attendeeQuery, (attendeeErr, attendeeResults) => {
                if (attendeeErr) {
                    console.error('Database query error in public-stats attendees:', attendeeErr);
                    return res.status(500).json({ error: 'Database error' });
                }

                // Set explicit headers to ensure proper JSON and CORS
                res.header("Access-Control-Allow-Origin", "*");
                res.header("Access-Control-Allow-Headers", "Content-Type, Accept");
                res.setHeader('Content-Type', 'application/json');
                
                // Return the data
                res.json({
                    summary: summaryResults || [],
                    totals: {
                        users: totalResults[0]?.total_users || 0,
                        badges: totalResults[0]?.total_badges || 0
                    },
                    attendees: attendeeResults || []
                });
                
                console.log('Public stats sent successfully');
            });
        });
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