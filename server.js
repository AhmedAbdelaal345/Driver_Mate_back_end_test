const express = require("express");
const cors = require("cors");
const multer = require("multer");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());

const upload = multer();

// Secret key for JWT
const SECRET = "DRIVER_MATE_SECRET_KEY";

// In-memory storage
let users = [];
let otps = {}; // { email: "123456" }

// ======================
// REGISTER
// ======================
app.post("/register", upload.none(), (req, res) => {
  const { name, email, password, isAgreed } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ status: false, message: "Missing fields" });
  }

  users.push({ name, email, password, isAgreed });

  res.json({
    status: true,
    message: "User registered successfully",
    data: { name, email }
  });
});

// ======================
// LOGIN + TOKEN
// ======================
app.post("/login", upload.none(), (req, res) => {
  const { email, password } = req.body;

  const user = users.find(
    (u) => u.email === email && u.password === password
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

// ======================
// REQUEST OTP
// ======================
app.post("/request-otp", upload.none(), (req, res) => {
  const { email } = req.body;

  const user = users.find((u) => u.email === email);
  if (!user) {
    return res.status(404).json({ status: false, message: "Email not found" });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  otps[email] = otp;

  res.json({
    status: true,
    message: "OTP generated",
    otp // انت هتستقبلها في الفلتر (لأن مفيش SMS حاليا)
  });
});

// ======================
// VERIFY OTP
// ======================
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

// ======================
// CHANGE PASSWORD
// ======================
app.post("/change-password", upload.none(), (req, res) => {
  const { email, oldPassword, newPassword } = req.body;

  const user = users.find(
    (u) => u.email === email && u.password === oldPassword
  );

  if (!user) {
    return res.status(401).json({
      status: false,
      message: "Old password is wrong"
    });
  }

  user.password = newPassword;

  res.json({
    status: true,
    message: "Password updated successfully"
  });
});

// ======================
// RAILWAY PORT
// ======================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on port " + PORT));
