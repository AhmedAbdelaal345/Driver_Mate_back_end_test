const express = require("express");
require("dotenv").config();
const cors = require("cors");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
app.use(cors());
app.use(express.json());

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fieldSize: 5 * 1024 * 1024 }
});

const SECRET = process.env.JWT_SECRET || "DRIVER_MATE_SECRET_KEY";
const SALT_ROUNDS = 10;

let users = [];
let otps = {};

const validateEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const validatePassword = (password) => password && password.length >= 6;

// =====================
// HOME
// =====================
app.get("/", (req, res) => {
  res.json({
    status: true,
    message: "Driver Mate Auth API (Vercel Serverless)",
    version: "1.0.0",
    endpoints: {
      register: "POST /api/register",
      login: "POST /api/login",
      requestOtp: "POST /api/request-otp",
      verifyOtp: "POST /api/verify-otp",
      changePassword: "POST /api/change-password",
      resetPassword: "POST /api/reset-password"
    }
  });
});

// =====================
// REGISTER
// =====================
app.post("/register", upload.none(), async (req, res) => {
  try {
    const { name, email, password, isAgreed } = req.body;

    if (!name || !email || !password)
      return res.status(400).json({ status: false, message: "Missing fields" });

    if (!validateEmail(email))
      return res.status(400).json({ status: false, message: "Invalid email" });

    if (!validatePassword(password))
      return res.status(400).json({ status: false, message: "Weak password" });

    if (users.find(u => u.email === email))
      return res.status(409).json({ status: false, message: "Email exists" });

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    const newUser = {
      id: users.length + 1,
      name,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);

    res.status(201).json({ status: true, message: "Registered", data: newUser });
  } catch (error) {
    res.status(500).json({ status: false, message: "Registration failed" });
  }
});

// =====================
// LOGIN
// =====================
app.post("/login", upload.none(), async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = users.find(u => u.email === email);
    if (!user) return res.status(401).json({ status: false, message: "Invalid login" });

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ status: false, message: "Invalid login" });

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: "24h" });

    res.json({ status: true, token, user });
  } catch (error) {
    res.status(500).json({ status: false, message: "Login failed" });
  }
});

// =====================
module.exports = app;
