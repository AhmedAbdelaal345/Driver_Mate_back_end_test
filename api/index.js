const express = require("express");
const cors = require("cors");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Resend } = require("resend");

const app = express();

// ==========================
//  MIDDLEWARE
// ==========================
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==========================
//  CONFIGURATION
// ==========================
const ACCESS_SECRET = process.env.ACCESS_SECRET || "DRIVER_MATE_ACCESS_SECRET_CHANGE_IN_PROD";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "DRIVER_MATE_REFRESH_SECRET_CHANGE_IN_PROD";
const RESEND_API_KEY = process.env.RESEND_API_KEY || "re_eD9AAvas_5PFurHBZ4jdWJTF3y4gf9RSY";

const SALT_ROUNDS = 10;
const OTP_EXPIRY = 10 * 60 * 1000; // 10 minutes

// Initialize Resend
const resend = new Resend(RESEND_API_KEY);

// Configure multer for form-data
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fieldSize: 5 * 1024 * 1024 }
});

// ==========================
//  IN-MEMORY STORAGE
//  WARNING: This resets on each cold start in Vercel!
//  Use a database (MongoDB, PostgreSQL, etc.) for production
// ==========================
let users = [];
let otps = {};

// ==========================
// HELPER FUNCTIONS
// ==========================
const validateEmail = (email) => {
  return email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
};

const validatePassword = (password) => {
  return password && password.length >= 6;
};

const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// ==========================
// EMAIL HELPER
// ==========================
async function sendOtpEmail(to, otp) {
  try {
    const result = await resend.emails.send({
      from: "Driver Mate <onboarding@resend.dev>",
      to,
      subject: "Your OTP Code - DriverMate",
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
          <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <h1 style="color: #333; text-align: center;">DriverMate</h1>
            <h2 style="color: #666; text-align: center;">Your OTP Code</h2>
            <div style="background-color: #f8f9fa; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0;">
              <h1 style="font-size: 36px; font-weight: bold; color: #007bff; margin: 0; letter-spacing: 5px;">${otp}</h1>
            </div>
            <p style="color: #666; text-align: center; margin-top: 20px;">This code will expire in 10 minutes.</p>
            <p style="color: #999; text-align: center; font-size: 12px; margin-top: 30px;">If you didn't request this code, please ignore this email.</p>
          </div>
        </body>
        </html>
      `
    });
    
    console.log("✅ Email sent successfully:", result);
    return true;
  } catch (err) {
    console.error("❌ Email send failed:", err.message);
    return false;
  }
}

// ==========================
// AUTH MIDDLEWARE
// ==========================
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return res.status(401).json({ 
      status: false, 
      message: "Access token required" 
    });
  }

  const token = authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ 
      status: false, 
      message: "Invalid token format" 
    });
  }

  jwt.verify(token, ACCESS_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ 
        status: false, 
        message: "Invalid or expired token" 
      });
    }

    req.user = decoded;
    next();
  });
}

// ==========================
// ROUTES
// ==========================

// HOME/HEALTH CHECK
app.get("/", (req, res) => {
  res.json({
    status: true,
    message: "DriverMate Auth API - Vercel Deployment",
    version: "1.0.0",
    timestamp: new Date().toISOString(),
    endpoints: {
      register: "POST /register",
      login: "POST /login",
      refreshToken: "POST /refresh-token",
      requestOtp: "POST /request-otp",
      verifyOtp: "POST /verify-otp",
      changePassword: "POST /change-password",
      resetPassword: "POST /reset-password",
      profile: "GET /profile"
    }
  });
});

// REGISTER
app.post("/register", upload.none(), async (req, res) => {
  try {
    const { name, email, password, isAgreed } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ 
        status: false, 
        message: "Name, email, and password are required" 
      });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ 
        status: false, 
        message: "Invalid email format" 
      });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({ 
        status: false, 
        message: "Password must be at least 6 characters" 
      });
    }

    if (isAgreed !== "true" && isAgreed !== true) {
      return res.status(400).json({ 
        status: false, 
        message: "You must accept terms and conditions" 
      });
    }

    // Check if user exists
    if (users.find(u => u.email === email)) {
      return res.status(409).json({ 
        status: false, 
        message: "Email already registered" 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Create user
    const newUser = {
      id: users.length + 1,
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);

    // Return user without password
    const { password: _, ...userWithoutPassword } = newUser;

    res.status(201).json({
      status: true,
      message: "Registration successful",
      data: userWithoutPassword
    });

  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ 
      status: false, 
      message: "Registration failed. Please try again." 
    });
  }
});

// LOGIN
app.post("/login", upload.none(), async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ 
        status: false, 
        message: "Email and password are required" 
      });
    }

    // Find user
    const user = users.find(u => u.email === email.toLowerCase().trim());
    if (!user) {
      return res.status(401).json({ 
        status: false, 
        message: "Invalid email or password" 
      });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ 
        status: false, 
        message: "Invalid email or password" 
      });
    }

    // Generate tokens
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

    // Store refresh token
    user.refreshToken = refreshToken;

    res.json({
      status: true,
      message: "Login successful",
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });

  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ 
      status: false, 
      message: "Login failed. Please try again." 
    });
  }
});

// REFRESH TOKEN
app.post("/refresh-token", upload.none(), (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ 
        status: false, 
        message: "Refresh token is required" 
      });
    }

    // Find user with this refresh token
    const user = users.find(u => u.refreshToken === refreshToken);
    if (!user) {
      return res.status(403).json({ 
        status: false, 
        message: "Invalid refresh token" 
      });
    }

    // Verify refresh token
    jwt.verify(refreshToken, REFRESH_SECRET, (err, decoded) => {
      if (err) {
        return res.status(403).json({ 
          status: false, 
          message: "Refresh token expired or invalid" 
        });
      }

      // Generate new access token
      const newAccessToken = jwt.sign(
        { id: user.id, email: user.email },
        ACCESS_SECRET,
        { expiresIn: "15m" }
      );

      res.json({
        status: true,
        message: "Token refreshed successfully",
        accessToken: newAccessToken
      });
    });

  } catch (error) {
    console.error("Refresh token error:", error);
    res.status(500).json({ 
      status: false, 
      message: "Failed to refresh token" 
    });
  }
});

// GET PROFILE
app.get("/profile", authenticateToken, (req, res) => {
  try {
    const user = users.find(u => u.email === req.user.email);
    
    if (!user) {
      return res.status(404).json({ 
        status: false, 
        message: "User not found" 
      });
    }

    res.json({
      status: true,
      data: {
        id: user.id,
        name: user.name,
        email: user.email,
        createdAt: user.createdAt
      }
    });

  } catch (error) {
    console.error("Profile error:", error);
    res.status(500).json({ 
      status: false, 
      message: "Failed to fetch profile" 
    });
  }
});

// REQUEST OTP
app.post("/request-otp", upload.none(), async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        status: false,
        message: "Email is required"
      });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({
        status: false,
        message: "Invalid email format"
      });
    }

    // Check if user exists
    const user = users.find(u => u.email === email.toLowerCase().trim());
    if (!user) {
      return res.status(404).json({
        status: false,
        message: "No account found with this email"
      });
    }

    // Generate OTP
    const otp = generateOTP();

    // Store OTP
    otps[email] = {
      code: otp,
      expiresAt: Date.now() + OTP_EXPIRY
    };

    // Send email
    const emailSent = await sendOtpEmail(email, otp);

    if (!emailSent) {
      return res.status(500).json({
        status: false,
        message: "Failed to send OTP email. Please try again."
      });
    }

    res.json({
      status: true,
      message: "OTP sent successfully to your email"
    });

  } catch (error) {
    console.error("Request OTP error:", error);
    res.status(500).json({
      status: false,
      message: "Failed to send OTP. Please try again."
    });
  }
});

// VERIFY OTP
app.post("/verify-otp", upload.none(), (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ 
        status: false, 
        message: "Email and OTP are required" 
      });
    }

    const otpData = otps[email];
    
    if (!otpData) {
      return res.status(400).json({ 
        status: false, 
        message: "No OTP found. Please request a new one." 
      });
    }

    if (Date.now() > otpData.expiresAt) {
      delete otps[email];
      return res.status(400).json({ 
        status: false, 
        message: "OTP has expired. Please request a new one." 
      });
    }

    if (otp.trim() !== otpData.code) {
      return res.status(400).json({ 
        status: false, 
        message: "Invalid OTP code" 
      });
    }

    // OTP is valid, delete it
    delete otps[email];

    res.json({ 
      status: true, 
      message: "OTP verified successfully" 
    });

  } catch (error) {
    console.error("Verify OTP error:", error);
    res.status(500).json({ 
      status: false, 
      message: "OTP verification failed" 
    });
  }
});

// CHANGE PASSWORD (Authenticated)
app.post("/change-password", upload.none(), authenticateToken, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
      return res.status(400).json({ 
        status: false, 
        message: "Old password and new password are required" 
      });
    }

    if (!validatePassword(newPassword)) {
      return res.status(400).json({ 
        status: false, 
        message: "New password must be at least 6 characters" 
      });
    }

    const user = users.find(u => u.email === req.user.email);

    if (!user) {
      return res.status(404).json({ 
        status: false, 
        message: "User not found" 
      });
    }

    // Verify old password
    const isOldPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if (!isOldPasswordValid) {
      return res.status(400).json({ 
        status: false, 
        message: "Current password is incorrect" 
      });
    }

    // Hash and update new password
    user.password = await bcrypt.hash(newPassword, SALT_ROUNDS);

    res.json({ 
      status: true, 
      message: "Password changed successfully" 
    });

  } catch (error) {
    console.error("Change password error:", error);
    res.status(500).json({ 
      status: false, 
      message: "Failed to change password" 
    });
  }
});

// RESET PASSWORD (With OTP verification)
app.post("/reset-password", upload.none(), async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
      return res.status(400).json({ 
        status: false, 
        message: "Email, OTP, and new password are required" 
      });
    }

    if (!validatePassword(newPassword)) {
      return res.status(400).json({ 
        status: false, 
        message: "Password must be at least 6 characters" 
      });
    }

    // Verify OTP
    const otpData = otps[email];
    
    if (!otpData) {
      return res.status(400).json({ 
        status: false, 
        message: "No OTP found. Please request a new one." 
      });
    }

    if (Date.now() > otpData.expiresAt) {
      delete otps[email];
      return res.status(400).json({ 
        status: false, 
        message: "OTP has expired. Please request a new one." 
      });
    }

    if (otp.trim() !== otpData.code) {
      return res.status(400).json({ 
        status: false, 
        message: "Invalid OTP code" 
      });
    }

    // Find user
    const user = users.find(u => u.email === email.toLowerCase().trim());
    if (!user) {
      return res.status(404).json({ 
        status: false, 
        message: "User not found" 
      });
    }

    // Update password
    user.password = await bcrypt.hash(newPassword, SALT_ROUNDS);
    
    // Clear OTP
    delete otps[email];

    res.json({ 
      status: true, 
      message: "Password reset successfully" 
    });

  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({ 
      status: false, 
      message: "Failed to reset password" 
    });
  }
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({
    status: false,
    message: "Endpoint not found",
    path: req.path
  });
});

// ==========================
// EXPORT FOR VERCEL
// ==========================
module.exports = app;