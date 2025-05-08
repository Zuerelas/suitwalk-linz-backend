const express = require('express');
const router = express.Router();

router.get('/example', (req, res) => {
    res.json({ message: 'Example route working' });
});

module.exports = router;