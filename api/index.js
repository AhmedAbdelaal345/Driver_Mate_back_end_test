const express = require("express");
require("dotenv").config();
const cors = require("cors");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
app.use(cors());
app.use(express.json());

// ==========================
//  JWT SECRETS
// ==========================
const ACCESS_SECRET = process.env.ACCESS_SECRET || "DRIVER_MATE_ACCESS";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "DRIVER_MATE_REFRESH";

const SALT_ROUNDS = 10;

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fieldSize: 5 * 1024 * 1024 }
});

// ==========================
//  In-memory storage (for testing)
// ==========================
let users = [];
let otps = {}; // { email: { code, expiresAt } }

// ==========================
// Helpers
// ==========================
const validateEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const validatePassword = (password) => password && password.length >= 6;

// ==========================
// HOME
// ==========================
app.get("/", (req, res) => {
  res.json({
    status: true,
    message: "Driver Mate Auth API (Vercel Serverless)",
    endpoints: {
      register: "POST /api/register",
      login: "POST /api/login",
      refreshToken: "POST /api/refresh-token",
      requestOtp: "POST /api/request-otp",
      verifyOtp: "POST /api/verify-otp",
      changePassword: "POST /api/change-password",
      resetPassword: "POST /api/reset-password",
      profile: "GET /api/profile"
    }
  });
});

// ==========================
// REGISTER
// ==========================
app.post("/register", upload.none(), async (req, res) => {
  try {
    const { name, email, password, isAgreed } = req.body;

    if (!name || !email || !password)
      return res.status(400).json({ status: false, message: "Missing fields" });

    if (!validateEmail(email))
      return res.status(400).json({ status: false, message: "Invalid email" });

    if (!validatePassword(password))
      return res.status(400).json({ status: false, message: "Weak password" });

    if (isAgreed !== "true" && isAgreed !== true)
      return res.status(400).json({ status: false, message: "Must accept terms" });

    if (users.find(u => u.email === email))
      return res.status(409).json({ status: false, message: "Email already exists" });

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    const newUser = {
      id: users.length + 1,
      name,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);

    res.status(201).json({
      status: true,
      message: "Registered successfully",
      data: newUser
    });

  } catch {
    res.status(500).json({ status: false, message: "Registration failed" });
  }
});

// ==========================
// LOGIN + TOKENS
// ==========================
app.post("/login", upload.none(), async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = users.find(u => u.email === email);
    if (!user)
      return res.status(401).json({ status: false, message: "Invalid credentials" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return res.status(401).json({ status: false, message: "Invalid credentials" });

    const accessToken = jwt.sign(
      { id: user.id, email: user.email },
      ACCESS_SECRET,
      { expiresIn: "15m" }
    );

    const refreshToken = jwt.sign(
      { id: user.id, email: user.email },
      REFRESH_SECRET,
      { expiresIn: "7d" }
    );

    user.refreshToken = refreshToken;

    res.json({
      status: true,
      message: "Login success",
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });

  } catch {
    res.status(500).json({ status: false, message: "Login failed" });
  }
});

// ==========================
// REFRESH TOKEN
// ==========================
app.post("/refresh-token", upload.none(), (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken)
      return res.status(400).json({ status: false, message: "Refresh token is required" });

    const user = users.find(u => u.refreshToken === refreshToken);
    if (!user)
      return res.status(403).json({ status: false, message: "Invalid refresh token" });

    jwt.verify(refreshToken, REFRESH_SECRET, (err, decoded) => {
      if (err)
        return res.status(403).json({ status: false, message: "Expired or invalid refresh token" });

      const newAccessToken = jwt.sign(
        { id: user.id, email: user.email },
        ACCESS_SECRET,
        { expiresIn: "15m" }
      );

      res.json({
        status: true,
        accessToken: newAccessToken
      });
    });

  } catch {
    res.status(500).json({ status: false, message: "Failed to refresh token" });
  }
});

// ==========================
// AUTH MIDDLEWARE
// ==========================
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header)
    return res.status(401).json({ status: false, message: "No token" });

  const token = header.split(" ")[1];

  jwt.verify(token, ACCESS_SECRET, (err, decoded) => {
    if (err)
      return res.status(401).json({ status: false, message: "Invalid/expired token" });

    req.user = decoded;
    next();
  });
}

// ==========================
// PROFILE
// ==========================
app.get("/profile", auth, (req, res) => {
  const user = users.find(u => u.email === req.user.email);
  if (!user)
    return res.status(404).json({ status: false, message: "User not found" });

  res.json({
    status: true,
    data: {
      id: user.id,
      name: user.name,
      email: user.email,
      createdAt: user.createdAt
    }
  });
});

// ==========================
// REQUEST OTP
// ==========================
app.post("/request-otp", upload.none(), async (req, res) => {
  try {
    const { email } = req.body;

    if (!validateEmail(email))
      return res.status(400).json({ status: false, message: "Invalid email" });

    const user = users.find(u => u.email === email);
    if (!user)
      return res.status(404).json({ status: false, message: "Email not found" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    otps[email] = {
      code: otp,
      expiresAt: Date.now() + 10 * 60 * 1000
    };

    console.log(`OTP for ${email}: ${otp}`);

    // ===== SEND EMAIL USING RESEND =====
    const { Resend } = require("resend");
    const resend = new Resend(process.env.RESEND_API_KEY);

    await resend.emails.send({
      from: "Driver Mate <onboarding@resend.dev>",
      to: email,
      subject: "Your OTP Code",
      html: `
        <h1>Your OTP Code</h1>
        <p>Here is your verification code:</p>
        <h2>${otp}</h2>
        <p>This code expires in 10 minutes.</p>
      `
    });

    res.json({
      status: true,
      message: "OTP sent to email"
    });

  } catch (error) {
    console.log("OTP EMAIL ERROR", error);
    res.status(500).json({ status: false, message: "OTP request failed" });
  }
});

// ==========================
// VERIFY OTP
// ==========================
app.post("/verify-otp", upload.none(), (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp)
      return res.status(400).json({ status: false, message: "Missing data" });

    const data = otps[email];
    if (!data)
      return res.status(400).json({ status: false, message: "No OTP found" });

    if (Date.now() > data.expiresAt)
      return res.status(400).json({ status: false, message: "OTP expired" });

    if (otp !== data.code)
      return res.status(400).json({ status: false, message: "Invalid OTP" });

    delete otps[email];

    res.json({ status: true, message: "OTP verified" });

  } catch {
    res.status(500).json({ status: false, message: "OTP verification failed" });
  }
});

// ==========================
// CHANGE PASSWORD
// ==========================
app.post("/change-password", upload.none(), auth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword)
      return res.status(400).json({ status: false, message: "Missing fields" });

    if (!validatePassword(newPassword))
      return res.status(400).json({ status: false, message: "Weak password" });

    const user = users.find(u => u.email === req.user.email);

    const valid = await bcrypt.compare(oldPassword, user.password);
    if (!valid)
      return res.status(400).json({ status: false, message: "Old password incorrect" });

    user.password = await bcrypt.hash(newPassword, SALT_ROUNDS);

    res.json({ status: true, message: "Password updated" });

  } catch {
    res.status(500).json({ status: false, message: "Failed to change password" });
  }
});

// ==========================
// RESET PASSWORD
// ==========================
app.post("/reset-password", upload.none(), async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    if (!email || !validatePassword(newPassword))
      return res.status(400).json({ status: false, message: "Invalid data" });

    const user = users.find(u => u.email === email);
    if (!user)
      return res.status(404).json({ status: false, message: "User not found" });

    user.password = await bcrypt.hash(newPassword, SALT_ROUNDS);

    res.json({ status: true, message: "Password reset" });

  } catch {
    res.status(500).json({ status: false, message: "Failed to reset password" });
  }
});

// ==========================
// EXPORT FOR VERCEL
// ==========================
module.exports = app;
