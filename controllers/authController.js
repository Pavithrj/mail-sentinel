const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

exports.register = async (req, res) => {
    try {
        let { name, email, password, role } = req.body;

        name = name?.trim();
        email = email?.trim();

        if (!name || !email || !password)
            return res.status(400).json({ message: "All fields are required" });

        if (name.length < 2)
            return res.status(400).json({ message: "Name must be at least 2 characters" });

        if (!/^[A-Za-z ]+$/.test(name))
            return res.status(400).json({ message: "Name should contain only alphabets" });

        if (!emailRegex.test(email))
            return res.status(400).json({ message: "Invalid email format" });

        if (!passwordRegex.test(password))
            return res.status(400).json({ message: "Password must have 8+ chars, uppercase, lowercase, number & special symbol" });

        const existingUser = await User.findOne({ email });

        if (existingUser)
            return res.status(400).json({ message: "Email already exists" });

        if (role === "admin") {
            const adminExists = await User.findOne({ role: "admin" });

            if (adminExists) {
                return res.status(403).json({ message: "Admin account already exists. Only one admin is allowed." });
            }
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await User.create({
            name,
            email,
            password: hashedPassword,
            role: role === "admin" ? "admin" : "user"
        });

        const token = jwt.sign(
            { id: newUser._id, email: newUser.email, role: newUser.role },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.status(201).json({
            message: "User registered successfully",
            token,
            user: {
                id: newUser._id,
                name: newUser.name,
                email: newUser.email,
                role: newUser.role
            }
        });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(400).json({ message: "Email already registered" });
        }

        return res.status(500).json({ message: "Server error", error: error.message });
    }
};

exports.login = async (req, res) => {
    try {
        let { email, password } = req.body;

        email = email?.trim();

        if (!email || !password)
            return res.status(400).json({ message: "Email & password required" });

        if (!emailRegex.test(email))
            return res.status(400).json({ message: "Invalid email format" });

        const user = await User.findOne({ email });

        if (!user)
            return res.status(400).json({ message: "Invalid credentials" });

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch)
            return res.status(400).json({ message: "Invalid credentials" });

        const token = jwt.sign(
            { id: user._id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.status(200).json({
            message: "Login successful",
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        return res.status(500).json({ message: "Server error", error: error.message });
    }
};

exports.getAllUsers = async (req, res) => {
    try {
        const users = await User.find({ role: "user" }).select("-password");
        res.json({ total: users.length, users });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

exports.getAllAdmins = async (req, res) => {
    try {
        const admins = await User.find({ role: "admin" }).select("-password");
        res.json({ total: admins.length, admins });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

exports.deleteUser = async (req, res) => {
    try {
        const userId = req.params.id;
        const user = await User.findByIdAndDelete(userId);

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        res.json({ message: "User deleted successfully" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

exports.deleteAdmin = async (req, res) => {
    try {
        const adminId = req.params.id;
        const admin = await User.findByIdAndDelete(adminId);

        if (!admin) {
            return res.status(404).json({ message: "Admin not found" });
        }

        res.json({ message: "Admin deleted successfully" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};
