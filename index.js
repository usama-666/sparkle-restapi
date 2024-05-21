const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000;
const SECRET_KEY = "asanfkdsojdsoafgafFSADCFSDFdsfdsfVXVCX";

// Middleware
app.use(bodyParser.json());

const users = [];

// Register route (to create users)
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ email, password: hashedPassword });
  res.status(201).send("User registered");
});

// Login route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find({ email: email });

  if (!user) {
    return res.status(400).send("Invalid email or password");
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    return res.status(400).send("Invalid email or password");
  }

  const token = jwt.sign({ id: user.email }, SECRET_KEY, { expiresIn: "1h" });

  res.status(200).json({ token });
});

// Middleware to authenticate JWT token
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.sendStatus(403);
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }

    req.user = user;
    next();
  });
};

// Protected route
app.get("/protected", authenticateJWT, (req, res) => {
  res.status(200).send("This is a protected route");
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
