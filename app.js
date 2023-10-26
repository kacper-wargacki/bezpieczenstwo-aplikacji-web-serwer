const express = require("express");
require("dotenv").config();
const { verifyToken } = require("./verifyToken.js");
const { sha256 } = require("js-sha256");
const jwt = require("jsonwebtoken");
const mssql = require("mssql");
const cors = require("cors");

const app = express();
const port = 3000;
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cors());

const config = {
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  options: {
    trustServerCertificate: true, // only for local development
  },
};

mssql.connect(config);

app.post("/createNote", async (req, res) => {
  const isVerified = await verifyToken(req.body.token);
  if (isVerified.status === 200) {
    const id = req.body.id;
    const note = req.body.note;
    const result = mssql.query`INSERT INTO notes(id, note) VALUES(${id}, ${note})`;
    res.status(200).json({ result });
  } else if (isVerified.status === 404) {
    res.status(404).json({ message: isVerified.message });
  } else if (isVerified.status === 400) {
    res.status(400).json({ message: isVerified.message });
  } else {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/deleteAllNotes", async (req, res) => {
  const isVerified = await verifyToken(req.body.token);
  if (isVerified.status === 200) {
    if (isVerified.decoded.userType !== "admin") {
      res
        .status(400)
        .json({ message: "You are not authorized to perform this action" });
    } else {
      const result = mssql.query`DELETE FROM notes`;
      res.status(200).json({ result: result.recordset });
    }
  } else if (isVerified.status === 404) {
    res.status(404).json({ message: isVerified.message });
  } else if (isVerified.status === 400) {
    res.status(400).json({ message: isVerified.message });
  } else {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/getNotes", async (req, res) => {
  const isVerified = await verifyToken(req.body.token);
  if (isVerified.status === 200) {
    const userId = isVerified.decoded.userId;
    const result = await mssql.query`SELECT * FROM notes WHERE id = ${userId}`;
    res.status(200).json({ result });
  } else if (isVerified.status === 404) {
    res.status(404).json({ message: isVerified.message });
  } else if (isVerified.status === 400) {
    res.status(400).json({ message: isVerified.message });
  } else {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const username = req.body.data.username;
    const password = sha256(req.body.data.password);
    const result = await mssql.query`SELECT * FROM users WHERE username = ${username} AND password = ${password}`;
    const user = result.recordset[0];
    if (!user) {
      res.status(404).json({ message: "User does not exist" });
    } else {
      const token = jwt.sign(
        { userId: user.id, username: user.username, userType: user.userType },
        process.env.JWT_SECRET,
        {
          expiresIn: "15m",
        }
      );
      res.status(200).json({ user, token, message: "Token OK" });
    }
  } catch (error) {
    res.status(500).json({ message: "Server error" });
    console.log(error);
  }
});

app.post("/register", async (req, res) => {
  try {
    const username = req.body.username;
    const result1 = await mssql.query`SELECT * FROM users WHERE username = ${username}`;
    const userExists = result1.recordset.length > 0;
    if (userExists) {
      res.status(409).json({ message: "User already exists" });
    } else {
      const password = sha256(req.body.password);
      const result = await mssql.query`INSERT INTO users(username, password) VALUES(${username}, ${password})`;
      res.status(200).json({ result });
    }
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
