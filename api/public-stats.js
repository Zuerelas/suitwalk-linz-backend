const mysql = require('mysql2');
require('dotenv').config();

module.exports = async (req, res) => {
    // Set more permissive CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept, Cache-Control, X-Requested-With');
    res.setHeader('Content-Type', 'application/json');
    
    // Handle OPTIONS request for CORS preflight
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    
    // Create database connection
    const db = mysql.createConnection({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        ssl: process.env.DB_SSL === 'true' ? true : undefined
    });
    
    try {
        // Connect to database
        db.connect();
        
        // Query for summary statistics
        const summaryResults = await new Promise((resolve, reject) => {
            db.query(`
                SELECT 
                    type,
                    COUNT(*) as count,
                    SUM(CASE WHEN badge = 1 THEN 1 ELSE 0 END) as badge_count
                FROM users
                GROUP BY type
                ORDER BY count DESC
            `, (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });
        
        // Query for total counts
        const totalResults = await new Promise((resolve, reject) => {
            db.query(`
                SELECT 
                    COUNT(*) as total_users,
                    SUM(CASE WHEN badge = 1 THEN 1 ELSE 0 END) as total_badges
                FROM users
            `, (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });
        
        // Query for attendee list (names only, no personal data)
        const attendeeResults = await new Promise((resolve, reject) => {
            db.query(`
                SELECT 
                    first_name,
                    type,
                    badge
                FROM users
                ORDER BY created_at DESC
            `, (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });
        
        // Send response
        const response = {
            summary: summaryResults || [],
            totals: {
                users: totalResults[0]?.total_users || 0,
                badges: totalResults[0]?.total_badges || 0
            },
            attendees: attendeeResults || []
        };
        
        return res.status(200).json(response);
    } catch (error) {
        console.error('Error in public-stats API:', error);
        return res.status(500).json({ error: 'Database error', message: error.message });
    } finally {
        db.end(); // Close the connection
    }
};