const express = require("express");
const cors = require("cors");
const app = express();

app.use(cors());
app.use(express.json());

let users = []; // Temporary in-memory DB

app.get("/", (req, res) => {
  res.send("Auth API is running...");
});

// REGISTER
app.post("/register", (req, res) => {
  const { name, email, password, isAgreed } = req.body;

  if (!name || !email || !password)
    return res.status(400).json({ status: false, message: "Missing fields" });

  users.push({ name, email, password, isAgreed });

  res.json({
    status: true,
    message: "User registered successfully",
    data: { name, email, isAgreed }
  });
});

// LOGIN
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email && u.password === password);

  if (!user)
    return res.status(401).json({ status: false, message: "Invalid email or password" });

  res.json({
    status: true,
    message: "Login success",
    token: "fake-jwt-token-123"
  });
});

app.listen(3000, () => console.log("Auth API running on port 3000"));
