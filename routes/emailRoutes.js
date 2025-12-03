const express = require('express');
const { protect, requireAdmin } = require('../middleware/authMiddleware');
const router = express.Router();

// simple protected test route
router.get('/protected-test', protect, (req, res) => {
    // req.user is available here
    res.json({
        success: true,
        message: 'Protected route accessed',
        user: { id: req.user._id, email: req.user.email, role: req.user.role }
    });
});

// admin-only route example
router.get('/admin-test', protect, requireAdmin, (req, res) => {
    res.json({ success: true, message: 'Admin route accessed' });
});

module.exports = router;
