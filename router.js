const express = require('express');
const router = express.Router();

// Example route
router.get('/example', (req, res) => {
    res.json({ message: 'Example route working' });
});

// Health check route
router.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// User-related routes
router.get('/users', (req, res) => {
    // Fetch users logic here
    res.json({ message: 'List of users' });
});

router.post('/users', (req, res) => {
    // Create user logic here
    res.json({ message: 'User created', data: req.body });
});

// Error handling for undefined routes
router.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

module.exports = router;