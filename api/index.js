const express = require("express");
require("dotenv").config();
const cors = require("cors");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Resend } = require("resend");

const app = express();
app.use(cors());
app.use(express.json());

// ==========================
//  SECRETS
// ==========================
const ACCESS_SECRET = process.env.ACCESS_SECRET || "DRIVER_MATE_ACCESS";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "DRIVER_MATE_REFRESH";
const RESEND_API_KEY = process.env.RESEND_API_KEY || "re_eD9AAvas_5PFurHBZ4jdWJTF3y4gf9RSY";

const resend = new Resend(RESEND_API_KEY);

const SALT_ROUNDS = 10;

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fieldSize: 5 * 1024 * 1024 }
});

// ==========================
// TEMP MEMORY DATABASE
// ==========================
let users = [];
let otps = {}; // { email: { code, expiresAt } }

const validateEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const validatePassword = (password) => password && password.length >= 6;

// ==========================
// HOME
// ==========================
app.get("/", (req, res) => {
  res.json({
    status: true,
    message: "Driver Mate Auth API (Serverless Ready)",
    version: "2.0.0"
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
      return res.status(409).json({ status: false, message: "Email already registered" });

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    const newUser = {
      id: users.length + 1,
      name,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);

    res.status(201).json({ status: true, message: "Registered successfully", data: newUser });

  } catch (err) {
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
      message: "Login successful",
      accessToken,
      refreshToken,
      user: { id: user.id, name: user.name, email: user.email }
    });

  } catch (err) {
    res.status(500).json({ status: false, message: "Login failed" });
  }
});

// ==========================
// REFRESH TOKEN
// ==========================
app.post("/refresh-token", upload.none(), async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken)
      return res.status(400).json({ status: false, message: "Refresh token required" });

    const user = users.find(u => u.refreshToken === refreshToken);
    if (!user)
      return res.status(403).json({ status: false, message: "Invalid refresh token" });

    jwt.verify(refreshToken, REFRESH_SECRET, (err) => {
      if (err)
        return res.status(403).json({ status: false, message: "Expired refresh token" });

      const newAccessToken = jwt.sign(
        { id: user.id, email: user.email },
        ACCESS_SECRET,
        { expiresIn: "15m" }
      );

      res.json({ status: true, accessToken: newAccessToken });
    });

  } catch (err) {
    res.status(500).json({ status: false, message: "Could not refresh token" });
  }
});

// ==========================
// AUTH MIDDLEWARE
// ==========================
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header)
    return res.status(401).json({ status: false, message: "Token required" });

  const token = header.split(" ")[1];

  jwt.verify(token, ACCESS_SECRET, (err, decoded) => {
    if (err)
      return res.status(401).json({ status: false, message: "Invalid token" });

    req.user = decoded;
    next();
  });
}

// ==========================
// REQUEST OTP (SEND EMAIL)
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

    console.log("OTP:", otp);

    // SEND EMAIL
    await resend.emails.send({
      from: "Driver Mate <noreply@drivermate.app>",
      to: email,
      subject: "Your OTP Code",
      html: `
        <h1>Your DriverMate OTP</h1>
        <p>Your verification code is:</p>
        <h2>${otp}</h2>
        <p>This code expires in 10 minutes.</p>
      `
    });

    res.json({ status: true, message: "OTP sent to email" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ status: false, message: "Failed to send OTP" });
  }
});

// ==========================
// VERIFY OTP
// ==========================
app.post("/verify-otp", upload.none(), (req, res) => {
  try {
    const { email, otp } = req.body;

    const data = otps[email];
    if (!data)
      return res.status(400).json({ status: false, message: "No OTP found" });

    if (Date.now() > data.expiresAt)
      return res.status(400).json({ status: false, message: "OTP expired" });

    if (otp !== data.code)
      return res.status(400).json({ status: false, message: "Invalid OTP" });

    delete otps[email];

    res.json({ status: true, message: "OTP verified" });

  } catch (err) {
    res.status(500).json({ status: false, message: "Verification failed" });
  }
});

// ==========================
// CHANGE PASSWORD
// ==========================
app.post("/change-password", upload.none(), auth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    const user = users.find(u => u.email === req.user.email);

    const valid = await bcrypt.compare(oldPassword, user.password);
    if (!valid)
      return res.status(400).json({ status: false, message: "Wrong old password" });

    user.password = await bcrypt.hash(newPassword, SALT_ROUNDS);

    res.json({ status: true, message: "Password updated" });

  } catch (err) {
    res.status(500).json({ status: false, message: "Password update failed" });
  }
});

// ==========================
// RESET PASSWORD
// ==========================
app.post("/reset-password", upload.none(), async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    const user = users.find(u => u.email === email);
    if (!user)
      return res.status(404).json({ status: false, message: "User not found" });

    user.password = await bcrypt.hash(newPassword, SALT_ROUNDS);

    res.json({ status: true, message: "Password reset successful" });

  } catch (err) {
    res.status(500).json({ status: false, message: "Password reset failed" });
  }
});

// ==========================
module.exports = app;
