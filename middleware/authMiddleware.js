const jwt = require('jsonwebtoken');
const User = require('../models/User');

exports.protect = async (req, res, next) => {
    try {
        let token;

        if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
            token = req.headers.authorization.split(" ")[1];
        }

        if (!token) {
            return res.status(401).json({ success: false, message: "Not authorized, token missing" });
        }

        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET);
        } catch (err) {
            return res.status(401).json({ success: false, message: "Invalid or expired token" });
        }

        const user = await User.findById(decoded.id).select("-password");
        if (!user) {
            return res.status(401).json({ success: false, message: "User no longer exists" });
        }

        req.user = user;
        next();
    } catch (error) {
        console.error("Auth middleware error:", error);
        return res.status(500).json({ success: false, message: "Server error in auth middleware" });
    }
};

exports.requireAdmin = (req, res, next) => {
    if (!req.user) return res.status(401).json({ success: false, message: "Not authorized" });
    if (req.user.role !== "admin") {
        return res.status(403).json({ success: false, message: "Admin access required" });
    }
    next();
};
