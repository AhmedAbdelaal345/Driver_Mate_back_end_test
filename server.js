const express = require("express");
const cors = require("cors");
const multer = require("multer");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());

const upload = multer();
const SECRET = "DRIVER_MATE_SECRET_KEY";

let users = [];
let otps = {};

// =====================
// HOME ROUTE
// =====================
app.get("/", (req, res) => {
  res.send("Driver Mate Auth API (FormData + JWT + OTP) is running...");
});

// =====================
// REGISTER
// =====================
app.post("/register", upload.none(), (req, res) => {
  console.log("REGISTER BODY:", req.body);

  const { name, email, password, isAgreed } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({
      status: false,
      message: "Missing fields"
    });
  }

  users.push({ name, email, password, isAgreed });

  res.json({
    status: true,
    message: "User registered successfully",
    data: { name, email, isAgreed }
  });
});

// =====================
// LOGIN + TOKEN
// =====================
app.post("/login", upload.none(), (req, res) => {
  console.log("LOGIN BODY:", req.body);

  const { email, password } = req.body;

  const user = users.find(
    u => u.email === email && u.password === password
  );

  if (!user) {
    return res.status(401).json({
      status: false,
      message: "Invalid email or password"
    });
  }

  const token = jwt.sign({ email }, SECRET, { expiresIn: "1h" });

  res.json({
    status: true,
    message: "Login success",
    token
  });
});

// =====================
// REQUEST OTP
// =====================
app.post("/request-otp", upload.none(), (req, res) => {
  const { email } = req.body;

  const user = users.find(u => u.email === email);
  if (!user)
    return res.status(404).json({ status: false, message: "Email not found" });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  otps[email] = otp;

  res.json({
    status: true,
    message: "OTP generated",
    otp
  });
});

// =====================
// VERIFY OTP
// =====================
app.post("/verify-otp", upload.none(), (req, res) => {
  const { email, otp } = req.body;

  if (otps[email] !== otp) {
    return res.status(400).json({
      status: false,
      message: "Invalid OTP"
    });
  }

  delete otps[email];

  res.json({
    status: true,
    message: "OTP verified"
  });
});

// =====================
// AUTH MIDDLEWARE
// =====================
function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header)
    return res
      .status(401)
      .json({ status: false, message: "No token provided" });

  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ status: false, message: "Invalid token" });
  }
}

// =====================
// CHANGE PASSWORD
// =====================
app.post("/change-password", upload.none(), auth, (req, res) => {
  const { oldPassword, newPassword } = req.body;

  const email = req.user.email;

  const user = users.find(u => u.email === email);

  if (!user)
    return res.status(404).json({ status: false, message: "User not found" });

  if (user.password !== oldPassword)
    return res
      .status(400)
      .json({ status: false, message: "Old password is incorrect" });

  user.password = newPassword;

  res.json({
    status: true,
    message: "Password updated successfully"
  });
});

// =====================
// RAILWAY PORT FIX
// =====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("SERVER STARTED ON PORT", PORT));
