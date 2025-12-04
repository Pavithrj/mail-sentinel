const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const signAccessToken = (payload) => {
    return jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_ACCESS_EXPIRES || "15m"
    });
};

const generateRefreshTokenString = () => {
    return crypto.randomBytes(parseInt(process.env.REFRESH_TOKEN_BYTES || 64)).toString("hex");
};

module.exports = { signAccessToken, generateRefreshTokenString };
