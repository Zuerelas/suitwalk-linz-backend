const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const sharp = require('sharp'); // Add this to your package.json dependencies
const cors = require('cors');
const ftp = require('basic-ftp');
require('dotenv').config(); 
//
const app = express();
app.use(bodyParser.json());
const router = express.Router();
app.use('/api/router', router); // Change the mount path to avoid conflicts

// Add these helper functions after imports
function createSuitwalksDbConnection() {
  try {
    const connection = mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME, // "suitwalks" database
      ssl: process.env.DB_SSL === 'true' ? true : undefined,
      connectTimeout: 10000 // 10 second timeout
    });
    
    // Add connection error handler
    connection.on('error', (err) => {
      console.error('Database connection error:', err);
      if (err.code === 'PROTOCOL_CONNECTION_LOST') {
        console.error('Database connection lost. Will not reconnect automatically.');
      }
    });
    
    return connection;
  } catch (error) {
    console.error('Error creating database connection:', error);
    throw error;
  }
}

function createPhotoDbConnection() {
  try {
    const connection = mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: 'Photos',
      ssl: process.env.DB_SSL === 'true' ? true : undefined,
      connectTimeout: 10000 // 10 second timeout
    });
    
    // Add connection error handler
    connection.on('error', (err) => {
      console.error('Photo database connection error:', err);
      if (err.code === 'PROTOCOL_CONNECTION_LOST') {
        console.error('Photo database connection lost. Will not reconnect automatically.');
      }
    });
    
    return connection;
  } catch (error) {
    console.error('Error creating photo database connection:', error);
    throw error;
  }
}

// Update the uploadToFTP function to handle directory structure and thumbnails
async function uploadToFTP(localFilePath, eventDate, photographerId, photographerName) {
  const client = new ftp.Client();
  client.ftp.verbose = true; // Enable verbose logging for debugging

  try {
    await client.access({
      host: process.env.FTP_HOST,
      port: process.env.FTP_PORT || 21,
      user: process.env.FTP_USER,
      password: process.env.FTP_PASSWORD,
      secure: false, // Set to true if using FTPS
    });

    console.log(`Connected to FTP server: ${process.env.FTP_HOST}`);

    // Extract filename from path
    const filename = path.basename(localFilePath);

    // MODIFIED: Ensure we use test.suitwalk-linz.at instead of httpdocs
    // Force the webRoot to be /test.suitwalk-linz.at regardless of environment variable
    const webRoot = '/test.suitwalk-linz.at';
    
    // Create the directory structure matching what the frontend expects
    // Format: /gallery/{eventDate}/{photographerId}/full/ and /gallery/{eventDate}/{photographerId}/thumbnails/
    const baseDir = `${webRoot}/gallery/${eventDate}/${photographerId}`;
    const fullDir = `${baseDir}/full`;
    const thumbnailDir = `${baseDir}/thumbnails`;

    // Ensure parent directories exist
    try {
      await client.ensureDir(`${webRoot}`);
      await client.ensureDir(`${webRoot}/gallery`);
      await client.ensureDir(`${webRoot}/gallery/${eventDate}`);
      await client.ensureDir(baseDir);
      await client.ensureDir(fullDir);
      await client.ensureDir(thumbnailDir);
    } catch (dirError) {
      console.log('Creating directories:', dirError);
      // Ignore errors - we'll try to create them
      await client.mkdir(`${webRoot}/gallery`, true);
      await client.mkdir(`${webRoot}/gallery/${eventDate}`, true);
      await client.mkdir(baseDir, true);
      await client.mkdir(fullDir, true);
      await client.mkdir(thumbnailDir, true);
    }

    // Upload the original file to the "full" directory
    const fullRemotePath = `${fullDir}/${filename}`;
    await client.uploadFrom(localFilePath, fullRemotePath);
    console.log(`Uploaded original file to FTP: ${fullRemotePath}`);

    // Create and upload thumbnail
    const thumbnailPath = `/tmp/thumbnail-${filename}`;
    await createThumbnail(localFilePath, thumbnailPath);
    
    // Upload thumbnail to thumbnails directory
    const thumbnailRemotePath = `${thumbnailDir}/${filename}`;
    await client.uploadFrom(thumbnailPath, thumbnailRemotePath);
    console.log(`Uploaded thumbnail to FTP: ${thumbnailRemotePath}`);

    // Delete the temporary thumbnail
    fs.unlinkSync(thumbnailPath);
    
    return {
      fullPath: fullRemotePath,
      thumbnailPath: thumbnailRemotePath
    };
  } catch (error) {
    console.error('Error uploading to FTP:', error);
    throw error;
  } finally {
    client.close();
  }
}

// Helper function to create thumbnails
async function createThumbnail(sourceFilePath, outputFilePath) {
  try {
    // Create a 300px width thumbnail while maintaining aspect ratio
    await sharp(sourceFilePath)
      .resize({ width: 300 })
      .jpeg({ quality: 80 })
      .toFile(outputFilePath);
    
    console.log(`Created thumbnail: ${outputFilePath}`);
    return true;
  } catch (error) {
    console.error(`Error creating thumbnail: ${error}`);
    throw error;
  }
}

// Then include your router and other middleware
console.log('Router module loaded');
app.use((req, res, next) => {
    console.log(`Request received: ${req.method} ${req.url}`);
    next();
});

// CORS Configuration
const corsOptions = {
  origin: function (origin, callback) {
    // For local development, allow requests with no origin (like curl or Postman)
    if (!origin) {
      return callback(null, true);
    }

    const allowedOrigins = [
      'https://test.suitwalk-linz.at', 
      'https://suitwalk-linz.at',
      /^http:\/\/localhost(:\d+)?$/  // Allow all localhost origins with any port
    ];
    
    // Check if origin matches any of the allowed origins
    // For regex patterns, we need to test them individually
    let isAllowed = false;
    for (const allowedOrigin of allowedOrigins) {
      if (typeof allowedOrigin === 'string' && allowedOrigin === origin) {
        isAllowed = true;
        break;
      } else if (allowedOrigin instanceof RegExp && allowedOrigin.test(origin)) {
        isAllowed = true;
        break;
      }
    }

    if (isAllowed) {
      callback(null, true);
    } else {
      console.log(`CORS blocked origin: ${origin}`);
      // TEMPORARILY allow all origins to debug the issue
      callback(null, true); // Allow all origins during development
      // callback(new Error('Not allowed by CORS')); // Uncomment this in production
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization'],
  credentials: true,
  maxAge: 86400 // Cache preflight requests for 24 hours
};

// Apply CORS middleware to all routes
app.use(cors(corsOptions));

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

    if (customType === 'photo_upload') {
      // Set type in the telegram data for later validation
      telegramData.type = 'photo_upload';
      
      // Redirect to the photo upload page with data in URL fragment
      // Using fragment instead of query to avoid exposing auth data in server logs
      const userDataParam = encodeURIComponent(JSON.stringify(telegramData));
      return res.redirect(`https://test.suitwalk-linz.at/#/galerie/upload?telegramAuth=${userDataParam}`);
    }
    
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
            } else if (customType === 'Abmelden') {
                // User wants to unregister, delete user
                const deleteQuery = `DELETE FROM users WHERE telegram_id = ?`;
                
                db.query(deleteQuery, [telegramData.id], (deleteErr, result) => {
                    if (deleteErr) {
                        console.error('Database delete error:', deleteErr);
                        return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=database_error');
                    }
                    
                    if (result.affectedRows === 0) {
                        console.log('No user found to delete');
                        return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=not_registered');
                    }
                    
                    console.log('User successfully deleted');
                    return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/abgemeldet');
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

// Handle user deletion
app.get('/api/telegram-delete', async (req, res) => {
    console.log('Received request to delete user');
    
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
            
            // Delete the user from the database
            const deleteQuery = `DELETE FROM users WHERE telegram_id = ?`;
            
            db.query(deleteQuery, [telegramData.id], (deleteErr, result) => {
                if (deleteErr) {
                    console.error('Database delete error:', deleteErr);
                    return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=database_error');
                }
                
                if (result.affectedRows === 0) {
                    console.log('No user found to delete');
                    return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/error?msg=not_registered');
                }
                
                console.log('User successfully deleted');
                return res.redirect('https://test.suitwalk-linz.at/#/anmeldung/abgemeldet');
            });
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

// Gallery API endpoints
app.get('/api/gallery/events', (req, res) => {
  // Return list of events with photo counts
  const photoDb = createPhotoDbConnection();
  
  const query = `
    SELECT 
      DATE_FORMAT(event_date, '%Y-%m-%d') as date,
      COUNT(*) as photo_count,
      COUNT(DISTINCT photographer_id) as photographer_count
    FROM photos
    GROUP BY event_date
    ORDER BY event_date DESC;
  `;
  
  photoDb.query(query, (err, results) => {
    if (err) {
      console.error('Database query error:', err);
      photoDb.end();
      return res.status(500).json({ error: 'Database error' });
    }
    
    res.json({ events: results });
    photoDb.end();
  });
});

app.get('/api/gallery/event/:date', (req, res) => {
  // Return photos for a specific event date
  const eventDate = req.params.date;
  const photoDb = createPhotoDbConnection();
  
  const query = `
    SELECT 
      p.id, p.filename, p.title, p.description, p.tags,
      p.photographer_id, ph.name as photographer_name 
    FROM photos p
    JOIN photographers ph ON p.photographer_id = ph.id
    WHERE DATE_FORMAT(p.event_date, '%Y-%m-%d') = ?
    ORDER BY p.id DESC;
  `;
  
  photoDb.query(query, [eventDate], (err, results) => {
    if (err) {
      console.error('Database query error:', err);
      photoDb.end();
      return res.status(500).json({ error: 'Database error' });
    }
    
    res.json({ photos: results });
    photoDb.end();
  });
});

// Replace all existing /api/gallery/upload endpoints with this single, well-structured implementation
app.post('/api/gallery/upload', async (req, res) => {
  console.log('==== PHOTO UPLOAD REQUEST RECEIVED ====');

  try {
    // Use Vercel's temporary directory for uploads
    const uploadDir = '/tmp/suitwalk-gallery';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }

    // Set up multer for file uploads
    const storage = multer.diskStorage({
      destination: uploadDir,
      filename: (req, file, cb) => {
        const timestamp = Date.now();
        const safeFilename = file.originalname.replace(/[^a-zA-Z0-9.]/g, '_');
        cb(null, `${timestamp}-${safeFilename}`);
      },
    });

    const upload = multer({ storage }).array('photos', 50);

    const processUpload = () => {
      return new Promise((resolve, reject) => {
        upload(req, res, (err) => {
          if (err) {
            console.error('Upload error:', err);
            reject(err);
          } else {
            resolve(req.files || []);
          }
        });
      });
    };

    const files = await processUpload();
    console.log(`Uploaded ${files.length} files to temporary directory`);

    if (files.length === 0) {
      return res.status(400).json({ error: 'No files uploaded' });
    }

    // Validate photographer key
    const photographerKey = req.body.photographerKey;
    if (!photographerKey || photographerKey !== process.env.PHOTOGRAPHER_API_KEY) {
      files.forEach(file => fs.unlinkSync(file.path)); // Delete temporary files
      return res.status(401).json({ error: 'Invalid photographer key' });
    }

    // Parse telegram data
    let telegramData;
    try {
      telegramData = JSON.parse(req.body.telegramData || '{}');
    } catch (error) {
      console.error('Error parsing telegramData:', error);
      files.forEach(file => fs.unlinkSync(file.path));
      return res.status(400).json({ error: 'Invalid telegramData format' });
    }

    // Connect to the database to find or create photographer
    const photoDb = createPhotoDbConnection();
    
    try {
      // Find or create photographer
      const [photographers] = await photoDb.promise().query(
        'SELECT id FROM photographers WHERE telegram_id = ?',
        [telegramData.id]
      );
      
      let photographerId;
      
      if (photographers.length === 0) {
        // Create new photographer
        const photographerName = `${telegramData.first_name || ''} ${telegramData.last_name || ''}`.trim();
        const [result] = await photoDb.promise().execute(
          'INSERT INTO photographers (name, telegram_id, website, bio) VALUES (?, ?, NULL, NULL)',
          [photographerName, telegramData.id]
        );
        photographerId = result.insertId;
        console.log(`Created new photographer with ID ${photographerId}`);
      } else {
        photographerId = photographers[0].id;
        console.log(`Using existing photographer with ID ${photographerId}`);
      }
      
      // Get other form fields
      const eventDate = req.body.eventDate || new Date().toISOString().split('T')[0];
      const title = req.body.title || '';
      const tags = req.body.tags || '';
      
      // Upload files to the Plesk server via FTP and insert to database
      for (const file of files) {
        try {
          // Get event date and photographer info
          const eventDate = req.body.eventDate || new Date().toISOString().split('T')[0];
          const title = req.body.title || '';
          const tags = req.body.tags || '';
          
          // Look up photographer name for directory structure
          const [photographerRows] = await photoDb.promise().query(
            'SELECT name FROM photographers WHERE id = ?',
            [photographerId]
          );
          
          const photographerName = photographerRows[0].name;
          
          // Upload the file and create directory structure
          const uploadPaths = await uploadToFTP(
            file.path, 
            eventDate, 
            photographerId, 
            photographerName
          );
          
          // Get image metadata
          const metadata = await sharp(file.path).metadata();
          
          // Insert into database
          await photoDb.promise().query(
            `INSERT INTO photos 
            (filename, event_date, photographer_id, title, tags, upload_date, download_count, file_size, width, height)
            VALUES (?, ?, ?, ?, ?, NOW(), 0, ?, ?, ?)`,
            [
              file.filename,
              eventDate,
              photographerId,
              title,
              tags,
              file.size,
              metadata.width,
              metadata.height
            ]
          );
          
          console.log(`File ${file.filename} uploaded and saved to database`);
          
          // Delete the temporary file
          fs.unlinkSync(file.path);
        } catch (error) {
          console.error(`Error processing file ${file.filename}:`, error);
          // Continue with other files even if one fails
        }
      }

      photoDb.end();
      res.status(200).json({ success: true, message: `${files.length} files uploaded successfully` });
    } catch (error) {
      photoDb.end();
      console.error('Error in photo upload process:', error);
      res.status(500).json({ error: 'Database error', details: error.message });
    }
  } catch (error) {
    console.error('Error in /api/gallery/upload:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
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
// Add this function for authenticating photographers or admins
function authenticateUser(req, res, next) {
  // Get token from Authorization header
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const token = authHeader.split(' ')[1];
  
  try {
    // For now, implement a simple token verification
    // In a production app, you should use JWT or a proper auth system
    if (token === process.env.PHOTOGRAPHER_API_KEY) {
      next();
    } else {
      res.status(401).json({ error: 'Invalid token' });
    }
  } catch (error) {
    console.error('Auth error:', error);
    res.status(401).json({ error: 'Authentication failed' });
  }
}


// Start server if not running as a module
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
  });
}

// Export the app for Vercel
module.exports = app;

// GET all photographers
app.get('/api/gallery/photographers', (req, res) => {
  const photoDb = createPhotoDbConnection();
  const query = 'SELECT * FROM photographers ORDER BY name';
  
  photoDb.query(query, (err, results) => {
    if (err) {
      console.error('Database error:', err);
      photoDb.end();
      return res.status(500).json({ error: 'Database error' });
    }
    
    res.json({ photographers: results });
    photoDb.end();
  });
});

// POST new photographer
app.post('/api/gallery/photographers', authenticateUser, (req, res) => {
  const photoDb = createPhotoDbConnection();
  const { name, telegram_id, website, bio } = req.body;
  
  if (!name) {
    photoDb.end();
    return res.status(400).json({ error: 'Photographer name is required' });
  }
  
  const query = 'INSERT INTO photographers (name, telegram_id, website, bio) VALUES (?, ?, ?, ?)';
  
  photoDb.query(query, [name, telegram_id || null, website || null, bio || null], (err, result) => {
    if (err) {
      console.error('Database error:', err);
      photoDb.end();
      return res.status(500).json({ error: 'Database error' });
    }
    
    res.status(201).json({ id: result.insertId, name });
    photoDb.end();
  });
});

// GET download photo with tracking
app.get('/api/gallery/download/:id', async (req, res) => {
  const photoId = req.params.id;
  const photoDb = createPhotoDbConnection();
  
  try {
    // Get photo info with photographer name
    const [rows] = await photoDb.promise().query(
      `SELECT 
        p.id, p.filename, p.event_date, 
        ph.name as photographer_name, ph.id as photographer_id
       FROM photos p
       JOIN photographers ph ON p.photographer_id = ph.id
       WHERE p.id = ?`,
      [photoId]
    );
    
    if (rows.length === 0) {
      photoDb.end();
      return res.status(404).json({ error: 'Photo not found' });
    }
    
    const photo = rows[0];
    const eventDate = photo.event_date.toISOString().split('T')[0];
    
    // MODIFIED: Force the webRoot to be /test.suitwalk-linz.at
    const webRoot = '/test.suitwalk-linz.at';
    
    // Build filepath matching the structure the frontend expects
    const filePath = path.join(
      webRoot,
      'gallery',
      eventDate,
      photo.photographer_id.toString(),
      'full',
      photo.filename
    );
    
    if (!fs.existsSync(filePath)) {
      photoDb.end();
      return res.status(404).json({ error: 'Photo file not found ', filePath });
    }
    
    // Increment download counter
    await photoDb.promise().execute(
      'UPDATE photos SET download_count = download_count + 1 WHERE id = ?',
      [photoId]
    );
    
    photoDb.end();
    
    // Set headers
    res.setHeader('Content-Disposition', `attachment; filename="${photo.filename}"`);
    res.setHeader('Content-Type', 'image/jpeg');
    
    // Stream the file
    const fileStream = fs.createReadStream(filePath);
    fileStream.pipe(res);
    
  } catch (error) {
    console.error('Download error:', error);
    photoDb.end();
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin login endpoint with enhanced debugging
app.post('/api/admin/login', (req, res) => {
  console.log('==== ADMIN LOGIN ENDPOINT TRIGGERED ====');
  console.log('Request headers:', {
    'content-type': req.headers['content-type'],
    'origin': req.headers.origin,
    'host': req.headers.host,
    'authorization': req.headers.authorization ? 'Present' : 'None'
  });
  
  console.log('Request body type:', typeof req.body);
  
  // Safety check for body parsing
  if (!req.body || typeof req.body !== 'object') {
    console.error('Invalid request body format:', req.body);
    return res.status(400).json({ error: 'Invalid request body' });
  }
  
  const { username, password } = req.body;
  console.log('Admin login attempt:', username);
  console.log('Password provided:', password ? '********' : 'None');
  
  // Log environment variables (partially masked)
  console.log('Environment variables check:', {
    'ADMIN_USERNAME exists': !!process.env.ADMIN_USERNAME,
    'ADMIN_PASSWORD exists': !!process.env.ADMIN_PASSWORD,
    'PHOTOGRAPHER_API_KEY exists': !!process.env.PHOTOGRAPHER_API_KEY,
    'Expected username': process.env.ADMIN_USERNAME ? 
      `${process.env.ADMIN_USERNAME.substring(0, 1)}****` : 'Not set',
    'Environment username comparison': username === process.env.ADMIN_USERNAME ? 'Match' : 'No match'
  });
  
  // Simple authentication check with detailed logging
  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    const token = process.env.PHOTOGRAPHER_API_KEY;
    console.log('Admin login successful:', username);
    console.log('Sending response with token');
    
    res.status(200).json({
      user: { username },
      token: token ? `${token.substring(0, 3)}...` : 'None'
    });
  } else {
    console.log('Authentication failed. Sending 401 response');
    console.log('Username match:', username === process.env.ADMIN_USERNAME);
    console.log('Password match:', password === process.env.ADMIN_PASSWORD);
    
    res.status(401).json({ error: 'Invalid credentials' });
  }
  console.log('==== ADMIN LOGIN ENDPOINT COMPLETED ====');
});

// Add a test endpoint to verify the server is responding
app.get('/api/test-endpoint', (req, res) => {
  console.log('Test endpoint called');
  res.json({ 
    status: 'ok', 
    message: 'Server is running and responding to API requests',
    env: {
      hasToken: !!process.env.TELEGRAM_BOT_TOKEN,
      hasPhotographerKey: !!process.env.PHOTOGRAPHER_API_KEY,
    }
  });
});

// Add this endpoint to get event dates for dropdown
app.get('/api/gallery/dates-events', (req, res) => {
  console.log('Event dates endpoint called');
  console.log('Request origin:', req.headers.origin);

  // EXPLICITLY SET CORS HEADERS FOR THIS ENDPOINT
  res.header('Access-Control-Allow-Origin', '*'); // Allow all origins for now
  res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');

  const photoDb = createPhotoDbConnection();

  // Query to get distinct event dates
  const query = `
    SELECT DISTINCT DATE_FORMAT(event_date, '%Y-%m-%d') as date
    FROM photos
    ORDER BY event_date DESC
  `;

  photoDb.query(query, (err, results) => {
    if (err) {
      console.error('Database query error:', err);
      photoDb.end();
      return res.status(500).json({ error: 'Database query error' });
    }

    // Extract dates from the query results
    const dates = results.map(row => row.date);

    // Always include today's date if no dates are found
    if (dates.length === 0) {
      dates.push(new Date().toISOString().split('T')[0]);
    }

    photoDb.end();
    
    // Add debugging headers to see in browser console
    res.header('X-Debug', 'dates-endpoint-response');
    res.json({ dates });
  });
});

// Modify the authentication for photo uploads
function authenticatePhotographer(req, res, next) {
  // 1. Check for API key
  const photographerKey = req.body.photographerKey;
  if (!photographerKey || photographerKey !== process.env.PHOTOGRAPHER_API_KEY) {
    return res.status(401).json({ error: 'Invalid photographer key' });
  }
  
  // 2. Check for Telegram data
  const telegramData = req.body.telegramData;
  if (!telegramData || !telegramData.id) {
    return res.status(401).json({ error: 'Missing Telegram authentication' });
  }
  
  // Check hash from Telegram to verify authenticity
  if (!verifyTelegramAuth(telegramData)) {
    return res.status(401).json({ error: 'Invalid Telegram authentication' });
  }
  
  // Authentication successful
  next();
}

// Add these endpoints after the existing gallery endpoints

// Get users who could be added as photographers
app.get('/api/admin/potential-photographers', authenticateUser, async (req, res) => {
  try {
    // Connect to both databases
    const suitwalksDb = createSuitwalksDbConnection();
    const photoDb = createPhotoDbConnection();
    
    // First get all existing photographer telegram_ids
    const [existingPhotographers] = await photoDb.promise().query(
      'SELECT telegram_id FROM photographers WHERE telegram_id IS NOT NULL'
    );
    
    // Create an array of existing telegram IDs for filtering
    const existingIds = existingPhotographers.map(p => p.telegram_id.toString());
    
    // Now get users from suitwalks DB who aren't already photographers
    const [users] = await suitwalksDb.promise().query(
      'SELECT telegram_id, first_name, last_name, username, photo_url, type FROM users ORDER BY first_name, last_name'
    );
    
    // Filter out users who are already photographers
    const potentialPhotographers = users.filter(user => 
      !existingIds.includes(user.telegram_id.toString())
    );
    
    photoDb.end();
    suitwalksDb.end();
    
    res.json({ users: potentialPhotographers });
    
  } catch (error) {
    console.error('Error fetching potential photographers:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add a user as photographer
app.post('/api/admin/add-photographer', authenticateUser, async (req, res) => {
  try {
    const { telegram_id } = req.body;
    
    if (!telegram_id) {
      return res.status(400).json({ error: 'Telegram ID is required' });
    }
    
    // Get user details from suitwalks DB
    const suitwalksDb = createSuitwalksDbConnection();
    const [users] = await suitwalksDb.promise().query(
      'SELECT telegram_id, first_name, last_name, username FROM users WHERE telegram_id = ?',
      [telegram_id]
    );
    
    if (users.length === 0) {
      suitwalksDb.end();
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = users[0];
    const photographerName = `${user.first_name} ${user.last_name || ''}`.trim();
    
    // Add to photographers table
    const photoDb = createPhotoDbConnection();
    
    // Check if photographer with this telegram_id already exists
    const [existing] = await photoDb.promise().query(
      'SELECT id FROM photographers WHERE telegram_id = ?',
      [telegram_id]
    );
    
    if (existing.length > 0) {
      photoDb.end();
      suitwalksDb.end();
      return res.status(409).json({ error: 'Photographer already exists' });
    }
    
    // Insert the new photographer
    const [result] = await photoDb.promise().execute(
      'INSERT INTO photographers (name, telegram_id, website, bio) VALUES (?, ?, NULL, NULL)',
      [photographerName, telegram_id]
    );
    
    photoDb.end();
    suitwalksDb.end();
    
    res.json({
      success: true,
      photographer: {
        id: result.insertId,
        name: photographerName,
        telegram_id: telegram_id,
        username: user.username
      }
    });
    
  } catch (error) {
    console.error('Error adding photographer:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Authentication middleware for admin routes
const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'Unauthorized: Missing or invalid token' });
  }
  
  next();
};

// Get photographers from Suitwalk database
app.get('/api/admin/photographers/suitwalk', authenticateAdmin, (req, res) => {
  const suitwalksDb = createSuitwalksDbConnection();
  
  suitwalksDb.query(
    `SELECT 
      id, telegram_id, first_name, last_name, username, photo_url, 
      type, badge, created_at 
     FROM users 
     WHERE type = 'Fotograf'
     ORDER BY first_name, last_name ASC`,
    (err, results) => {
      suitwalksDb.end();
      
      if (err) {
        console.error('Error fetching Suitwalk photographers:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      res.json({ photographers: results });
    }
  );
});

// Get photographers from Gallery database
app.get('/api/admin/photographers/gallery', authenticateAdmin, (req, res) => {
  const photoDb = createPhotoDbConnection();
  
  photoDb.query(
    `SELECT 
      id, name, telegram_id, website, bio
     FROM photographers 
     ORDER BY name ASC`,
    (err, results) => {
      photoDb.end();
      
      if (err) {
        console.error('Error fetching gallery photographers:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      // Get photo counts for each photographer
      const photoDb2 = createPhotoDbConnection();
      photoDb2.query(
        `SELECT photographer_id, COUNT(*) as count FROM photos GROUP BY photographer_id`,
        (err, photoCounts) => {
          photoDb2.end();
          
          if (err) {
            console.error('Error fetching photo counts:', err);
            return res.json({ photographers: results });
          }
          
          // Map photo counts to photographers
          const countMap = {};
          photoCounts.forEach(row => {
            countMap[row.photographer_id] = row.count;
          });
          
          // Add photo count to each photographer
          results.forEach(photographer => {
            photographer.photo_count = countMap[photographer.id] || 0;
          });
          
          res.json({ photographers: results });
        }
      );
    }
  );
});

// Add a photographer from Suitwalk to Gallery
app.post('/api/admin/photographers/add', authenticateAdmin, (req, res) => {
  const { suitwalkId } = req.body;
  
  if (!suitwalkId) {
    return res.status(400).json({ error: 'Missing suitwalk photographer ID' });
  }
  
  // Get photographer details from Suitwalk database
  const suitwalksDb = createSuitwalksDbConnection();
  
  suitwalksDb.query(
    `SELECT 
      id, first_name, last_name, telegram_id, photo_url
     FROM users 
     WHERE id = ?`,
    [suitwalkId],
    (err, results) => {
      suitwalksDb.end();
      
      if (err || results.length === 0) {
        console.error('Error fetching Suitwalk photographer:', err);
        return res.status(500).json({ error: 'Failed to fetch photographer details' });
      }
      
      const photographer = results[0];
      // Create name from first and last name
      const name = `${photographer.first_name} ${photographer.last_name || ''}`.trim();
      
      // Check if photographer already exists in Gallery database
      const photoDb = createPhotoDbConnection();
      
      photoDb.query(
        'SELECT id FROM photographers WHERE telegram_id = ?',
        [photographer.telegram_id || null],
        (err, existingResults) => {
          if (err) {
            photoDb.end();
            console.error('Error checking existing photographer:', err);
            return res.status(500).json({ error: 'Database error' });
          }
          
          if (existingResults.length > 0) {
            photoDb.end();
            return res.status(409).json({ 
              error: 'Photographer already exists in gallery database',
              existingId: existingResults[0].id
            });
          }
          
          // Add photographer to Gallery database
          photoDb.query(
            `INSERT INTO photographers 
              (name, telegram_id, website, bio) 
             VALUES (?, ?, NULL, NULL)`,
            [
              name,
              photographer.telegram_id || null
            ],
            (err, result) => {
              photoDb.end();
              
              if (err) {
                console.error('Error adding photographer to gallery:', err);
                return res.status(500).json({ error: 'Failed to add photographer to gallery' });
              }
              
              res.json({ 
                success: true, 
                message: 'Photographer added successfully',
                photographerId: result.insertId
              });
            }
          );
        }
      );
    }
  );
});

// Update existing photographer in Gallery database
app.put('/api/admin/photographers/:id', authenticateAdmin, (req, res) => {
  const { id } = req.params;
  const { name, telegram_id, website, bio } = req.body;
  
  const photoDb = createPhotoDbConnection();
  
  photoDb.query(
    `UPDATE photographers 
     SET name = ?, telegram_id = ?, website = ?, bio = ?
     WHERE id = ?`,
    [name, telegram_id || null, website || null, bio || null, id],
    (err, result) => {
      photoDb.end();
      
      if (err) {
        console.error('Error updating photographer:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Photographer not found' });
      }
      
      res.json({ success: true, message: 'Photographer updated successfully' });
    }
  );
});

// Delete photographer from Gallery database
app.delete('/api/admin/photographers/:id', authenticateAdmin, (req, res) => {
  const { id } = req.params;
  const photoDb = createPhotoDbConnection();
  
  // Check if photographer has photos
  photoDb.query(
    'SELECT COUNT(*) as photoCount FROM photos WHERE photographer_id = ?',
    [id],
    (err, results) => {
      if (err) {
        photoDb.end();
        console.error('Error checking photographer photos:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (results[0].photoCount > 0) {
        photoDb.end();
        return res.status(409).json({ 
          error: 'Cannot delete photographer with existing photos',
          photoCount: results[0].photoCount
        });
      }
      
      // Delete photographer if they have no photos
      photoDb.query(
        'DELETE FROM photographers WHERE id = ?',
        [id],
        (err, result) => {
          photoDb.end();
          
          if (err) {
            console.error('Error deleting photographer:', err);
            return res.status(500).json({ error: 'Database error' });
          }
          
          if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Photographer not found' });
          }
          
          res.json({ success: true, message: 'Photographer deleted successfully' });
        }
      );
    }
  );
});

// Add this debug middleware specifically for the photo upload endpoint
app.use('/api/gallery/upload', (req, res, next) => {
  console.log('==== PHOTO UPLOAD REQUEST ====');
  console.log('Content-Type:', req.headers['content-type']);
  console.log('Has req.body:', !!req.body);
  if (req.body) {
    console.log('Body keys:', Object.keys(req.body));
    if (req.body.photographerKey) {
      console.log('Has photographer key');
    }
    if (req.body.telegramData) {
      console.log('Has telegramData object');
    }
    // Check for flat keys that might be Telegram data
    const telegramKeys = ['id', 'first_name', 'last_name', 'username', 'photo_url', 'auth_date', 'hash'];
    const hasTelegramKeys = telegramKeys.some(key => req.body[key]);
    if (hasTelegramKeys) {
      console.log('Has individual Telegram keys');
    }
  }
  next();
});

// Also fix your TelegramLoginWidget to store data properly
app.get('/api/test-endpoint', (req, res) => {
  console.log('Test endpoint called');
  res.json({ 
    status: 'ok', 
    message: 'Server is running and responding to API requests',
    env: {
      hasToken: !!process.env.TELEGRAM_BOT_TOKEN,
      hasPhotographerKey: !!process.env.PHOTOGRAPHER_API_KEY,
    }
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

// ===== ADMIN AUTHENTICATION MIDDLEWARE =====
const verifyAdminToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  const token = authHeader.split(' ')[1];
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    if (!decoded.isAdmin) {
      return res.status(403).json({ error: 'Not authorized as admin' });
    }
    
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// ===== ADMIN API ENDPOINTS =====

// Dashboard statistics endpoint - replace verifyAdminToken with authenticateAdmin
app.get('/api/admin/dashboard', authenticateAdmin, async (req, res) => {
  console.log('Admin dashboard request received');
  try {
    // Connect to Photo database
    const photoDb = createPhotoDbConnection();
    
    // Get total photos count
    const [photoResults] = await photoDb.promise().query(
      'SELECT COUNT(*) as totalPhotos FROM photos'
    );
    
    // Get total photographers count
    const [photographerResults] = await photoDb.promise().query(
      'SELECT COUNT(*) as totalPhotographers FROM photographers'
    );
    
    // Get total downloads count
    const [downloadResults] = await photoDb.promise().query(
      'SELECT SUM(download_count) as totalDownloads FROM photos'
    );
    
    // Get recent uploads (last 10)
    const [recentUploads] = await photoDb.promise().query(
      `SELECT 
        p.id, p.filename, p.title, p.upload_date, p.event_date, p.photographer_id,
        ph.name as photographer_name
       FROM photos p
       JOIN photographers ph ON p.photographer_id = ph.id
       ORDER BY p.upload_date DESC
       LIMIT 10`
    );
    
    // Get photos per event statistics
    const [photosByEvent] = await photoDb.promise().query(
      `SELECT 
        DATE_FORMAT(event_date, '%Y-%m-%d') as event_date,
        COUNT(*) as photoCount
       FROM photos
       GROUP BY DATE_FORMAT(event_date, '%Y-%m-%d')
       ORDER BY event_date DESC
       LIMIT 5`
    );
    
    // Format results before sending
    const formattedRecentUploads = recentUploads.map(upload => ({
      ...upload,
      upload_date: upload.upload_date.toISOString(),
      event_date: upload.event_date.toISOString().split('T')[0]
    }));
    
    photoDb.end();
    
    res.json({
      totalPhotos: photoResults[0].totalPhotos,
      totalPhotographers: photographerResults[0].totalPhotographers,
      totalDownloads: downloadResults[0].totalDownloads || 0,
      recentUploads: formattedRecentUploads,
      photosByEvent: photosByEvent
    });
  } catch (error) {
    console.error('Error fetching dashboard data:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Get all Suitwalk photographers - replace verifyAdminToken with authenticateAdmin
app.get('/api/admin/photographers/suitwalk', authenticateAdmin, async (req, res) => {
  try {
    console.log('Fetching Suitwalk photographers...');
    const suitwalksDb = createSuitwalksDbConnection();
    
    // First check if database connection is working by counting users
    const [countResult] = await suitwalksDb.promise().query('SELECT COUNT(*) as total FROM users');
    console.log('Total users in database:', countResult[0].total);
    
    // Get all users regardless of type to see what's in the table
    const [photographers] = await suitwalksDb.promise().query(
      `SELECT 
        id, telegram_id, first_name, last_name, username, photo_url, 
        type, badge, created_at 
       FROM users 
       ORDER BY first_name, last_name ASC`
    );
    
    console.log(`Found ${photographers.length} users in the database`);
    
    // Log the first user (with sensitive info redacted) to verify data structure
    if (photographers.length > 0) {
      console.log('Sample user data structure:', {
        id: photographers[0].id,
        first_name: photographers[0].first_name,
        type: photographers[0].type,
        has_telegram_id: !!photographers[0].telegram_id
      });
    }
    
    suitwalksDb.end();
    
    res.json({ photographers });
  } catch (error) {
    console.error('Error fetching Suitwalk photographers:', error);
    res.status(500).json({ error: 'Failed to fetch photographers', details: error.message });
  }
});

// Get all gallery photographers - already using authenticateAdmin, no change needed

// Add a new photographer to gallery - replace verifyAdminToken with authenticateAdmin
app.post('/api/admin/photographers/gallery', authenticateAdmin, async (req, res) => {
  try {
    const { name, telegram_id, website, bio } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Photographer name is required' });
    }
    
    const photoDb = createPhotoDbConnection();
    
    const [result] = await photoDb.promise().execute(
      'INSERT INTO photographers (name, telegram_id, website, bio) VALUES (?, ?, ?, ?)',
      [name, telegram_id || null, website || null, bio || null]
    );
    
    photoDb.end();
    
    res.status(201).json({ 
      success: true, 
      photographer: { 
        id: result.insertId,
        name,
        telegram_id,
        website,
        bio
      } 
    });
  } catch (error) {
    console.error('Error adding photographer:', error);
    res.status(500).json({ error: 'Failed to add photographer', details: error.message });
  }
});

// Get photos endpoint (with pagination and filters) - replace verifyAdminToken with authenticateAdmin
app.get('/api/admin/photos', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, photographer, eventDate, sortBy = 'upload_date', sortDir = 'DESC' } = req.query;
    const offset = (page - 1) * limit;
    
    // Validate sort parameters
    const allowedSortFields = ['id', 'upload_date', 'event_date', 'download_count', 'file_size'];
    const allowedSortDirs = ['ASC', 'DESC'];
    
    const actualSortBy = allowedSortFields.includes(sortBy) ? sortBy : 'upload_date';
    const actualSortDir = allowedSortDirs.includes(sortDir.toUpperCase()) ? sortDir.toUpperCase() : 'DESC';
    
    const photoDb = createPhotoDbConnection();
    
    // Build the base query
    let query = `
      SELECT 
        p.id, p.filename, p.title, p.description, p.event_date, p.upload_date,
        p.download_count, p.file_size, p.width, p.height, p.tags,
        ph.id as photographer_id, ph.name as photographer_name
      FROM photos p
      JOIN photographers ph ON p.photographer_id = ph.id
      WHERE 1=1
    `;
    
    const queryParams = [];
    
    // Add filters if provided
    if (photographer) {
      query += ' AND ph.id = ?';
      queryParams.push(photographer);
    }
    
    if (eventDate) {
      query += ' AND DATE_FORMAT(p.event_date, "%Y-%m-%d") = ?';
      queryParams.push(eventDate);
    }
    
    // Add sorting and pagination
    query += ` ORDER BY p.${actualSortBy} ${actualSortDir} LIMIT ? OFFSET ?`;
    queryParams.push(parseInt(limit), parseInt(offset));
    
    // Execute the query
    const [photos] = await photoDb.promise().query(query, queryParams);
    
    // Count total photos (for pagination)
    let countQuery = `
      SELECT COUNT(*) as total
      FROM photos p
      JOIN photographers ph ON p.photographer_id = ph.id
      WHERE 1=1
    `;
    
    const countParams = [];
    
    if (photographer) {
      countQuery += ' AND ph.id = ?';
      countParams.push(photographer);
    }
    
    if (eventDate) {
      countQuery += ' AND DATE_FORMAT(p.event_date, "%Y-%m-%d") = ?';
      countParams.push(eventDate);
    }
    
    const [countResult] = await photoDb.promise().query(countQuery, countParams);
    
    photoDb.end();
    
    // Format date fields
    const formattedPhotos = photos.map(photo => ({
      ...photo,
      upload_date: photo.upload_date.toISOString(),
      event_date: photo.event_date.toISOString().split('T')[0]
    }));
    
    res.json({
      photos: formattedPhotos,
      total: countResult[0].total,
      page: parseInt(page),
      limit: parseInt(limit),
      totalPages: Math.ceil(countResult[0].total / limit)
    });
  } catch (error) {
    console.error('Error fetching photos:', error);
    res.status(500).json({ error: 'Failed to fetch photos', details: error.message });
  }
});