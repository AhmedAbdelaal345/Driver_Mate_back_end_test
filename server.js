const express = require("express");
const cors = require("cors");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
app.use(cors());
app.use(express.json());

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fieldSize: 5 * 1024 * 1024 // 5MB for safety
  }
});
const SECRET = process.env.JWT_SECRET || "DRIVER_MATE_SECRET_KEY";
const SALT_ROUNDS = 10;

let users = [];
let otps = {};

// =====================
// UTILITY FUNCTIONS
// =====================
const validateEmail = (email) => {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
};

const validatePassword = (password) => {
  return password && password.length >= 6;
};

// =====================
// HOME ROUTE
// =====================
app.get("/", (req, res) => {
  res.json({
    status: true,
    message: "Driver Mate Auth API",
    version: "1.0.0",
    endpoints: {
      register: "POST /register",
      login: "POST /login",
      requestOtp: "POST /request-otp",
      verifyOtp: "POST /verify-otp",
      changePassword: "POST /change-password (requires auth)",
      resetPassword: "POST /reset-password"
    }
  });
});

// =====================
// REGISTER
// =====================
app.post("/register", upload.none(), async (req, res) => {
  try {
    console.log("REGISTER REQUEST:", { ...req.body, password: "***" });
    
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
        message: "You must agree to terms and conditions"
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
      name,
      email,
      password: hashedPassword,
      isAgreed: true,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);

    res.status(201).json({
      status: true,
      message: "User registered successfully",
      data: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        createdAt: newUser.createdAt
      }
    });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({
      status: false,
      message: "Registration failed"
    });
  }
});

// =====================
// LOGIN + TOKEN
// =====================
app.post("/login", upload.none(), async (req, res) => {
  try {
    console.log("LOGIN REQUEST:", { email: req.body.email });
    
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        status: false,
        message: "Email and password are required"
      });
    }

    const user = users.find(u => u.email === email);
    
    if (!user) {
      return res.status(401).json({
        status: false,
        message: "Invalid email or password"
      });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    
    if (!isValidPassword) {
      return res.status(401).json({
        status: false,
        message: "Invalid email or password"
      });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      status: true,
      message: "Login successful",
      token,
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
      message: "Login failed"
    });
  }
});

// =====================
// REQUEST OTP
// =====================
app.post("/request-otp", upload.none(), (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !validateEmail(email)) {
      return res.status(400).json({
        status: false,
        message: "Valid email is required"
      });
    }

    const user = users.find(u => u.email === email);
    
    if (!user) {
      return res.status(404).json({
        status: false,
        message: "Email not found"
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    otps[email] = {
      code: otp,
      expiresAt: Date.now() + 10 * 60 * 1000 // 10 minutes
    };

    console.log(`OTP for ${email}: ${otp}`);

    res.json({
      status: true,
      message: "OTP sent successfully",
      // Remove this in production - only for testing
      otp: process.env.NODE_ENV === "development" ? otp : undefined
    });
  } catch (error) {
    console.error("Request OTP error:", error);
    res.status(500).json({
      status: false,
      message: "Failed to send OTP"
    });
  }
});

// =====================
// VERIFY OTP
// =====================
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
        message: "No OTP found for this email"
      });
    }

    if (Date.now() > otpData.expiresAt) {
      delete otps[email];
      return res.status(400).json({
        status: false,
        message: "OTP has expired"
      });
    }

    if (otpData.code !== otp) {
      return res.status(400).json({
        status: false,
        message: "Invalid OTP"
      });
    }

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

// =====================
// AUTH MIDDLEWARE
// =====================
function auth(req, res, next) {
  const header = req.headers.authorization;
  
  if (!header) {
    return res.status(401).json({
      status: false,
      message: "No token provided"
    });
  }

  const token = header.split(" ")[1];
  
  if (!token) {
    return res.status(401).json({
      status: false,
      message: "Invalid token format"
    });
  }

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({
      status: false,
      message: "Invalid or expired token"
    });
  }
}

// =====================
// CHANGE PASSWORD
// =====================
app.post("/change-password", upload.none(), auth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const email = req.user.email;

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

    const user = users.find(u => u.email === email);
    
    if (!user) {
      return res.status(404).json({
        status: false,
        message: "User not found"
      });
    }

    const isValidPassword = await bcrypt.compare(oldPassword, user.password);
    
    if (!isValidPassword) {
      return res.status(400).json({
        status: false,
        message: "Old password is incorrect"
      });
    }

    user.password = await bcrypt.hash(newPassword, SALT_ROUNDS);

    res.json({
      status: true,
      message: "Password updated successfully"
    });
  } catch (error) {
    console.error("Change password error:", error);
    res.status(500).json({
      status: false,
      message: "Failed to change password"
    });
  }
});

// =====================
// RESET PASSWORD
// =====================
app.post("/reset-password", upload.none(), async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
      return res.status(400).json({
        status: false,
        message: "Email and new password are required"
      });
    }

    if (!validatePassword(newPassword)) {
      return res.status(400).json({
        status: false,
        message: "Password must be at least 6 characters"
      });
    }

    const user = users.find(u => u.email === email);
    
    if (!user) {
      return res.status(404).json({
        status: false,
        message: "User not found"
      });
    }

    user.password = await bcrypt.hash(newPassword, SALT_ROUNDS);

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

// =====================
// GET USER PROFILE
// =====================
app.get("/profile", auth, (req, res) => {
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

// =====================
// ERROR HANDLER
// =====================
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({
    status: false,
    message: "Internal server error"
  });
});

// =====================
// 404 HANDLER
// =====================
app.use((req, res) => {
  res.status(404).json({
    status: false,
    message: "Route not found"
  });
});

// =====================
// START SERVER
// =====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Driver Mate Auth API running on port ${PORT}`);
  console.log(`📝 Environment: ${process.env.NODE_ENV || "development"}`);
});