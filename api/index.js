// Import your main server app
const app = require('../server');

// Fix for Vercel's path-to-regexp error: Ensure the route patterns in the server are valid
// Export for Vercel serverless function
module.exports = (req, res) => {
    if (!req.url.startsWith('/api')) {
        res.status(404).send('Not Found');
        return;
    }
    app(req, res);
};