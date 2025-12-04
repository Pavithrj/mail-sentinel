const mongoose = require('mongoose');

const refreshTokenSchema = new mongoose.Schema(
    {
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User", required: true
        },
        token: {
            type: String,
            required: true
        },
        createdAt: {
            type: Date,
            default: Date.now
        },
        expiresAt: {
            type: Date,
            required: true
        },
        revoked: {
            type: Boolean,
            default: false
        },
        replacedByToken: {
            type: String,
            default: null
        }
    }
);

module.exports = mongoose.model("RefreshToken", refreshTokenSchema);
