const express = require("express");
const cors = require("cors");
const multer = require("multer");

const app = express();
app.use(cors());

// Multer config to parse FormData
const upload = multer();

// Temporary in-memory database
let users = [];

// Home route
app.get("/", (req, res) => {
  res.send("Driver Mate Auth API with FormData is running...");
});

// REGISTER (FormData)
app.post("/register", upload.none(), (req, res) => {
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

// LOGIN (FormData)
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

  res.json({
    status: true,
    message: "Login success",
    token: "fake-jwt-token"
  });
});

// IMPORTANT for Railway
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on port " + PORT));
