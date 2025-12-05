// routes/adminAuthRoutes.js
const express = require('express');
const { registerAdmin, loginAdmin } = require('../controllers/adminAuthController');
const router = express.Router();

// Admin Register
router.post('/register', registerAdmin);

// Admin Login
router.post('/login', loginAdmin);

module.exports = router;
