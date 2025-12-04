const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const protectedRoutes = require('./routes/emailRoutes');

dotenv.config();

if (!process.env.JWT_SECRET) {
    console.warn("⚠️ WARNING: JWT_SECRET is missing. Tokens may not verify correctly.");
}

const PORT = process.env.PORT || 5000;
const app = express();

app.use(cors());
app.use(express.json());
app.use(cookieParser());

app.use("/api/auth", authRoutes);
app.use("/api/test", protectedRoutes);

app.get("/", (req, res) => {
    res.send("MailSentinel backend API is running 🚀");
});

app.listen(PORT, async () => {
    await connectDB();

    console.log(`MailSentinel backend API is running on http://localhost:${PORT}`);
});
