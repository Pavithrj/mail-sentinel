const express = require('express');
const { protect, requireAdmin } = require('../middleware/authMiddleware');
const router = express.Router();

router.get("/protected-test", protect, (req, res) => {
    res.json({
        success: true,
        message: "Protected route accessed",
        user: { id: req.user._id, email: req.user.email, role: req.user.role }
    });
});

router.get("/admin-test", protect, requireAdmin, (req, res) => {
    res.json({ success: true, message: "Admin route accessed" });
});

module.exports = router;
