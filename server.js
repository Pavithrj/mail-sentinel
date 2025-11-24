const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');

// const teamRoutes = require('./routes/teamRoutes');
// const errorHandler = require('./middleware/error');
// const uiRoutes = require('./routes/uiRoutes');

const PORT = process.env.PORT || 5000;

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

app.use('/api/auth', authRoutes);
// app.use("/api/team", teamRoutes);

// app.use(errorHandler);

app.get('/', (req, res) => {
    res.send('MailSentinel backend API is running 🚀');
});

app.listen(PORT, async () => {
    await connectDB();

    console.log(`MailSentinel backend API is running on http://localhost:${PORT}`);
});
