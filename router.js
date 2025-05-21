const express = require('express');
const router = express.Router();

// Basic route to test if router is working
router.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Router is working',
    timestamp: new Date().toISOString()
  });
});

router.get('/example', (req, res) => {
    res.json({ message: 'Example route working' });
});

// You can add additional routes here if needed
// router.get('/another-route', (req, res) => { ... });

module.exports = router;