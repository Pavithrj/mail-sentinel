const express = require('express');
const { register, login, getAllUsers, getAllAdmins, deleteUser, deleteAdmin } = require('../controllers/authController');
const router = express.Router();

router.post("/register", register);
router.post("/login", login);

router.get("/users", getAllUsers);
router.get("/admins", getAllAdmins);

router.delete("/user/:id", deleteUser);
router.delete("/admin/:id", deleteAdmin);

module.exports = router;
