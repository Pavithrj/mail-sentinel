const jwt = require('jsonwebtoken');
const User = require('../models/User');

exports.protect = async (req, res, next) => {
    try {
        let token;

        const authHeader = req.headers.authorization || req.headers.Authorization;

        if (authHeader && typeof authHeader === "string") {
            const parts = authHeader.split(" ");

            if (parts.length === 2 && parts[0].toLowerCase() === "bearer") {
                token = parts[1];
            }
        }

        if (!token && req.headers["x-auth-token"]) {
            token = req.headers["x-auth-token"];
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
    if (!req.user)
        return res.status(401).json({ success: false, message: "Not authorized" });

    if (req.user.role !== "admin") {
        return res.status(403).json({ success: false, message: "Admin access required" });
    }

    next();
};
