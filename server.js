const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const sharp = require('sharp'); // Add this to your package.json dependencies
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

// Add these helper functions after imports
function createSuitwalksDbConnection() {
  return mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME, // suitwalks
    ssl: process.env.DB_SSL === 'true' ? true : undefined
  });
}

function createPhotoDbConnection() {
  return mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: 'Photo',
    ssl: process.env.DB_SSL === 'true' ? true : undefined
  });
}

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
      ph.name as photographer_name 
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

// Add upload endpoint for authenticated photographers
app.post('/api/gallery/upload', authenticateUser, (req, res) => {
  const uploadDir = path.join(__dirname, 'public', 'gallery');
  
  // Create base uploads directory if it doesn't exist
  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
  }
  
  const upload = multer({
    storage: multer.diskStorage({
      destination: (req, file, cb) => {
        const { eventDate, photographerId } = req.body;
        
        // Create both full and thumbnail directories
        const fullDir = path.join(uploadDir, eventDate, photographerId.toString(), 'full');
        const thumbDir = path.join(uploadDir, eventDate, photographerId.toString(), 'thumbnails');
        
        // Create directories if they don't exist
        fs.mkdirSync(fullDir, { recursive: true });
        fs.mkdirSync(thumbDir, { recursive: true });
        
        cb(null, fullDir); // Store originals in full dir
      },
      filename: (req, file, cb) => {
        // Generate safer filenames
        const timestamp = Date.now();
        const originalName = file.originalname.replace(/[^a-zA-Z0-9.]/g, '_');
        cb(null, `${timestamp}-${originalName}`);
      }
    }),
    limits: {
      fileSize: 15 * 1024 * 1024 // 15MB limit
    }
  }).array('photos', 50); // Accept up to 50 photos at once
  
  upload(req, res, async (err) => {
    if (err) {
      console.error('Upload error:', err);
      return res.status(500).json({ error: 'File upload error', details: err.message });
    }
    
    try {
      const { eventDate, photographerId, tags, title } = req.body;
      const files = req.files || [];
      
      if (files.length === 0) {
        return res.status(400).json({ error: 'No files uploaded' });
      }
      
      const photoDb = createPhotoDbConnection();
      
      // Process each file
      for (const file of files) {
        // Create thumbnail path
        const thumbDir = path.join(uploadDir, eventDate, photographerId.toString(), 'thumbnails');
        const thumbPath = path.join(thumbDir, file.filename);
        
        // Get dimensions with sharp
        const metadata = await sharp(file.path).metadata();
        
        // Generate thumbnail
        await sharp(file.path)
          .resize(400, null, { fit: 'inside' })
          .jpeg({ quality: 80 })
          .toFile(thumbPath);
        
        // Save to database
        const query = `
          INSERT INTO photos (
            filename, 
            event_date, 
            photographer_id, 
            file_size, 
            width, 
            height, 
            title,
            tags
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `;
        
        await photoDb.promise().execute(
          query,
          [
            file.filename,
            eventDate,
            photographerId,
            file.size,
            metadata.width,
            metadata.height,
            title || null,
            tags || null
          ]
        );
      }
      
      photoDb.end();
      
      res.status(200).json({ 
        success: true, 
        message: `${files.length} files uploaded successfully`,
        files: files.map(f => f.filename)
      });
      
    } catch (error) {
      console.error('Error during upload processing:', error);
      res.status(500).json({ error: 'Upload processing error', details: error.message });
    }
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

// New module for handling file uploads
module.exports = async (req, res) => {
    // Handle CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    
    if (req.method === 'OPTIONS') {
      return res.status(200).end();
    }
    
    // Create database connection
    const db = mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: "Photo", // Dont change th
      ssl: process.env.DB_SSL === 'true' ? true : undefined
    });
    
    try {
      // Authorization logic here
      
      // Process files with multer
      const storage = multer.diskStorage({
        destination: (req, file, cb) => {
          const { eventDate, photographerId } = req.body;
          const dir = path.join(__dirname, '../public/gallery', eventDate, photographerId);
          
          if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
          }
          
          cb(null, dir);
        },
        filename: (req, file, cb) => {
          cb(null, Date.now() + '-' + file.originalname);
        }
      });
      
      const upload = multer({ storage });
      
      // Handle the upload
      upload.array('photos')(req, res, async (err) => {
        if (err) {
          console.error('Upload error:', err);
          return res.status(500).json({ error: 'File upload error' });
        }
        
        const { eventDate, photographerId } = req.body;
        const files = req.files;
        
        // Save file info to database
        try {
          for (const file of files) {
            const query = `
              INSERT INTO photos 
              (filename, event_date, photographer_id, file_size) 
              VALUES (?, ?, ?, ?)
            `;
            
            await db.execute(query, [
              file.filename,
              eventDate,
              photographerId,
              file.size
            ]);
          }
          
          res.status(200).json({ success: true, count: files.length });
        } catch (dbError) {
          console.error('Database error:', dbError);
          res.status(500).json({ error: 'Database error', details: dbError.message });
        }
      });
    } catch (error) {
      console.error('Server error:', error);
      res.status(500).json({ error: 'Server error', details: error.message });
    } finally {
      db.end();
    }
  };

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

// Implement complete file upload with thumbnail generation
app.post('/api/gallery/upload', authenticateUser, (req, res) => {
  const uploadDir = path.join(__dirname, 'public', 'gallery');
  
  // Create base uploads directory if it doesn't exist
  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
  }
  
  const upload = multer({
    storage: multer.diskStorage({
      destination: (req, file, cb) => {
        const { eventDate, photographerId } = req.body;
        
        // Create both full and thumbnail directories
        const fullDir = path.join(uploadDir, eventDate, photographerId.toString(), 'full');
        const thumbDir = path.join(uploadDir, eventDate, photographerId.toString(), 'thumbnails');
        
        // Create directories if they don't exist
        fs.mkdirSync(fullDir, { recursive: true });
        fs.mkdirSync(thumbDir, { recursive: true });
        
        cb(null, fullDir); // Store originals in full dir
      },
      filename: (req, file, cb) => {
        // Generate safer filenames
        const timestamp = Date.now();
        const originalName = file.originalname.replace(/[^a-zA-Z0-9.]/g, '_');
        cb(null, `${timestamp}-${originalName}`);
      }
    }),
    limits: {
      fileSize: 15 * 1024 * 1024 // 15MB limit
    }
  }).array('photos', 50); // Accept up to 50 photos at once
  
  upload(req, res, async (err) => {
    if (err) {
      console.error('Upload error:', err);
      return res.status(500).json({ error: 'File upload error', details: err.message });
    }
    
    try {
      const { eventDate, photographerId, tags, title } = req.body;
      const files = req.files || [];
      
      if (files.length === 0) {
        return res.status(400).json({ error: 'No files uploaded' });
      }
      
      const photoDb = createPhotoDbConnection();
      
      // Process each file
      for (const file of files) {
        // Create thumbnail path
        const thumbDir = path.join(uploadDir, eventDate, photographerId.toString(), 'thumbnails');
        const thumbPath = path.join(thumbDir, file.filename);
        
        // Get dimensions with sharp
        const metadata = await sharp(file.path).metadata();
        
        // Generate thumbnail
        await sharp(file.path)
          .resize(400, null, { fit: 'inside' })
          .jpeg({ quality: 80 })
          .toFile(thumbPath);
        
        // Save to database
        const query = `
          INSERT INTO photos (
            filename, 
            event_date, 
            photographer_id, 
            file_size, 
            width, 
            height, 
            title,
            tags
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `;
        
        await photoDb.promise().execute(
          query,
          [
            file.filename,
            eventDate,
            photographerId,
            file.size,
            metadata.width,
            metadata.height,
            title || null,
            tags || null
          ]
        );
      }
      
      photoDb.end();
      
      res.status(200).json({ 
        success: true, 
        message: `${files.length} files uploaded successfully`,
        files: files.map(f => f.filename)
      });
      
    } catch (error) {
      console.error('Error during upload processing:', error);
      res.status(500).json({ error: 'Upload processing error', details: error.message });
    }
  });
});

// GET download photo with tracking
app.get('/api/gallery/download/:id', async (req, res) => {
  const photoId = req.params.id;
  const photoDb = createPhotoDbConnection();
  
  try {
    // Get photo info
    const [rows] = await photoDb.promise().query(
      `SELECT 
        p.id, p.filename, p.event_date, ph.name as photographer_name, ph.id as photographer_id
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
    const filePath = path.join(
      __dirname,
      'public',
      'gallery', 
      eventDate,
      photo.photographer_id.toString(),
      'full',
      photo.filename
    );
    
    if (!fs.existsSync(filePath)) {
      photoDb.end();
      return res.status(404).json({ error: 'Photo file not found' });
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

// Admin login endpoint
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  
  // Simple authentication check
  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    const token = process.env.PHOTOGRAPHER_API_KEY;
    
    res.json({
      user: { username },
      token: token
    });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Add this endpoint to get event dates for dropdown
app.get('/api/gallery/event-dates', (req, res) => {
  const photoDb = createPhotoDbConnection();
  
  // Check for existing dates in photos table
  const photoDatesQuery = `
    SELECT DISTINCT DATE_FORMAT(event_date, '%Y-%m-%d') as date
    FROM photos
    ORDER BY event_date DESC
  `;
  
  // Get dates from suitwalks database too
  const suitwalksDb = createSuitwalksDbConnection();
  const suitwalkDatesQuery = `
    SELECT DISTINCT DATE_FORMAT(date, '%Y-%m-%d') as date
    FROM events
    WHERE date >= DATE_SUB(NOW(), INTERVAL 1 YEAR)
    ORDER BY date DESC
  `;
  
  photoDb.query(photoDatesQuery, (err, photoResults) => {
    if (err) {
      photoDb.end();
      return res.status(500).json({ error: 'Database error' });
    }
    
    suitwalksDb.query(suitwalkDatesQuery, (err, eventResults) => {
      suitwalksDb.end();
      photoDb.end();
      
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      // Combine both results and remove duplicates
      const allDates = [...photoResults, ...eventResults].map(item => item.date);
      const uniqueDates = [...new Set(allDates)].sort().reverse();
      
      res.json({ dates: uniqueDates });
    });
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

// Replace the old authenticateUser with this for photo uploads
app.post('/api/gallery/upload', authenticatePhotographer, (req, res) => {
  const uploadDir = path.join(__dirname, 'public', 'gallery');
  
  // Get photographer details from Telegram data
  const telegramData = req.body.telegramData;
  const photographerName = telegramData.first_name + (telegramData.last_name ? ' ' + telegramData.last_name : '');
  
  // Create or get photographer ID
  const photoDb = createPhotoDbConnection();
  
  // Find or create photographer based on Telegram ID
  photoDb.query(
    'SELECT id FROM photographers WHERE telegram_id = ?',
    [telegramData.id],
    (err, results) => {
      if (err) {
        photoDb.end();
        return res.status(500).json({ error: 'Database error' });
      }
      
      let photographerId;
      
      if (results.length === 0) {
        // Create new photographer
        photoDb.query(
          'INSERT INTO photographers (name, telegram_id, username) VALUES (?, ?, ?)',
          [photographerName, telegramData.id, telegramData.username || ''],
          (err, result) => {
            if (err) {
              photoDb.end();
              return res.status(500).json({ error: 'Database error' });
            }
            
            photographerId = result.insertId;
            processUpload(photographerId);
          }
        );
      } else {
        // Use existing photographer
        photographerId = results[0].id;
        processUpload(photographerId);
      }
    }
  );
  
  function processUpload(photographerId) {
    // Continue with the upload process
    // Using the existing multer configuration
    const upload = multer({
      storage: multer.diskStorage({
        destination: (req, file, cb) => {
          const { eventDate } = req.body;
          
          // Create both full and thumbnail directories
          const fullDir = path.join(uploadDir, eventDate, photographerId.toString(), 'full');
          const thumbDir = path.join(uploadDir, eventDate, photographerId.toString(), 'thumbnails');
          
          // Create directories if they don't exist
          fs.mkdirSync(fullDir, { recursive: true });
          fs.mkdirSync(thumbDir, { recursive: true });
          
          cb(null, fullDir); // Store originals in full dir
        },
        filename: (req, file, cb) => {
          // Generate safer filenames
          const timestamp = Date.now();
          const originalName = file.originalname.replace(/[^a-zA-Z0-9.]/g, '_');
          cb(null, `${timestamp}-${originalName}`);
        }
      }),
      limits: {
        fileSize: 15 * 1024 * 1024 // 15MB limit
      }
    }).array('photos', 50);
    
    upload(req, res, async (err) => {
      // Existing upload handling code
      if (err) {
        console.error('Upload error:', err);
        return res.status(500).json({ error: 'File upload error', details: err.message });
      }
      
      try {
        const { eventDate, tags, title } = req.body;
        const files = req.files || [];
        
        if (files.length === 0) {
          photoDb.end();
          return res.status(400).json({ error: 'No files uploaded' });
        }
        
        // Process each file
        for (const file of files) {
          // Create thumbnail path
          const thumbDir = path.join(uploadDir, eventDate, photographerId.toString(), 'thumbnails');
          const thumbPath = path.join(thumbDir, file.filename);
          
          // Get dimensions with sharp
          const metadata = await sharp(file.path).metadata();
          
          // Generate thumbnail
          await sharp(file.path)
            .resize(400, null, { fit: 'inside' })
            .jpeg({ quality: 80 })
            .toFile(thumbPath);
          
          // Save to database
          await photoDb.promise().execute(
            `INSERT INTO photos (
              filename, 
              event_date, 
              photographer_id, 
              file_size, 
              width, 
              height, 
              title,
              tags
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
              file.filename,
              eventDate,
              photographerId,
              file.size,
              metadata.width,
              metadata.height,
              title || null,
              tags || null
            ]
          );
        }
        
        photoDb.end();
        
        res.status(200).json({ 
          success: true, 
          message: `${files.length} files uploaded successfully`,
          files: files.map(f => f.filename)
        });
        
      } catch (error) {
        photoDb.end();
        console.error('Error during upload processing:', error);
        res.status(500).json({ error: 'Upload processing error', details: error.message });
      }
    });
  }
});