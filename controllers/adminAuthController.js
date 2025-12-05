// controllers/adminAuthController.js
const bcrypt = require('bcryptjs');
const dayjs = require('dayjs');
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');
const { signAccessToken, generateRefreshTokenString } = require('../utils/tokenUtil');

// VALIDATIONS
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const passwordRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

// -------------- ADMIN REGISTER --------------
exports.registerAdmin = async (req, res) => {
    try {
        let { name, email, password, adminSecretKey } = req.body;

        // A secret key to prevent random people from registering as admin
        if (!adminSecretKey || adminSecretKey !== process.env.ADMIN_SECRET_KEY) {
            return res.status(403).json({ message: 'Unauthorized to create admin' });
        }

        name = name?.trim();
        email = email?.trim();

        if (!name || !email || !password)
            return res.status(400).json({ message: 'All fields are required' });

        if (name.length < 2)
            return res.status(400).json({ message: 'Name must be at least 2 characters' });

        if (!/^[A-Za-z ]+$/.test(name))
            return res.status(400).json({ message: 'Name should contain only letters and spaces' });

        if (!emailRegex.test(email))
            return res.status(400).json({ message: 'Invalid email format' });

        if (!passwordRegex.test(password))
            return res.status(400).json({
                message:
                    'Password must be 8+ chars including uppercase, lowercase, number, special char'
            });

        const existing = await User.findOne({ email });
        if (existing) return res.status(400).json({ message: 'Admin already exists with this email' });

        const hashed = await bcrypt.hash(password, 10);

        // Create ADMIN
        const admin = await User.create({
            name,
            email,
            password: hashed,
            role: 'admin'
        });

        return res.status(201).json({
            message: 'Admin registered successfully',
            admin: {
                id: admin._id,
                name: admin.name,
                email: admin.email,
                role: admin.role
            }
        });
    } catch (err) {
        console.error('Admin Register Error:', err);
        return res.status(500).json({ message: 'Server error' });
    }
};

// -------------- ADMIN LOGIN --------------
exports.loginAdmin = async (req, res) => {
    try {
        let { email, password } = req.body;

        if (!email || !password)
            return res.status(400).json({ message: 'Email and password are required' });

        const admin = await User.findOne({ email, role: 'admin' });
        if (!admin) return res.status(404).json({ message: 'Admin not found' });

        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

        // Generate Access Token
        const accessToken = signAccessToken({ id: admin._id, role: admin.role });

        // Generate Refresh Token
        const refreshTokenString = generateRefreshTokenString();
        const expiresAt = dayjs().add(7, 'day').toDate();

        await RefreshToken.create({
            user: admin._id,
            token: refreshTokenString,
            expiresAt
        });

        res.cookie('refreshToken', refreshTokenString, {
            httpOnly: true,
            secure: process.env.COOKIE_SECURE === 'true',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.status(200).json({
            message: 'Admin login successful',
            accessToken,
            admin: { id: admin._id, name: admin.name, email: admin.email, role: admin.role }
        });
    } catch (err) {
        console.error('Admin Login Error:', err);
        return res.status(500).json({ message: 'Server error' });
    }
};
