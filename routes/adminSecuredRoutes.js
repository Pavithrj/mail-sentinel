// routes/adminRoutes.js

const express = require('express');
const router = express.Router();
const adminAuth = require('../middleware/adminAuth');

// Example secured admin route
router.get('/dashboard', adminAuth, (req, res) => {
    res.json({ message: 'Admin Dashboard Access Granted' });
});

module.exports = router;
