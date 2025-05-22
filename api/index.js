const app = require('../server');

// Export a request handler function as required by Vercel serverless
module.exports = (req, res) => {
  // Forward the request to your Express app
  return app(req, res);
};