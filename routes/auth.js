const express = require("express");
const bcrypt = require("bcryptjs");
const db = require("../db");
const router = express.Router();

// REGISTER
router.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    console.log("Register Request:", req.body); // debug

    if (!email || !password) {
      return res.status(400).json({ error: "Missing fields" });
    }

    // Check if email already exists
    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, row) => {
      if (err) {
        console.error("DB Select Error:", err);
        return res.status(500).json({ error: "Database error" });
      }

      if (row) {
        console.log("Email already exists:", email);
        return res.status(400).json({ error: "Email already exists" });
      }

      // Hash password
      const hashed = await bcrypt.hash(password, 10);

      // Insert user
      db.run(
        "INSERT INTO users (email, password) VALUES (?, ?)",
        [email, hashed],
        function (err) {
          if (err) {
            console.error("DB Insert Error:", err);
            return res.status(500).json({ error: "Registration failed" });
          }
          console.log("User registered:", email);
          res.json({ message: "User registered successfully" });
        }
      );
    });
  } catch (err) {
    console.error("Registration Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// LOGIN
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log("Login Request:", req.body); // debug

    if (!email || !password) {
      return res.status(400).json({ error: "Missing fields" });
    }

    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
      if (err) {
        console.error("DB Select Error:", err);
        return res.status(500).json({ error: "Database error" });
      }

      if (!user) {
        return res.status(400).json({ error: "Invalid credentials" });
      }

      const valid = await bcrypt.compare(password, user.password);
      if (!valid) {
        return res.status(400).json({ error: "Invalid credentials" });
      }

      // Store session
      req.session.user = { id: user.id, email: user.email };
      res.json({ message: "Login successful", user: req.session.user });
    });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET CURRENT USER
router.get("/me", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Not logged in" });
  res.json({ user: req.session.user });
});

// LOGOUT
router.post("/logout", (req, res) => {
  req.session.destroy();
  res.json({ message: "Logged out successfully" });
});

// DASHBOARD (protected route)
router.get("/dashboard", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Not authorized" });
  }

  res.json({ message: `Welcome to your dashboard, ${req.session.user.email}!` });
});


// CHECK EMAIL AVAILABILITY
router.post("/check-email", (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email is required" });

  db.get("SELECT * FROM users WHERE email = ?", [email], (err, row) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (row) return res.json({ exists: true });
    return res.json({ exists: false });
  });
});

module.exports = router;
