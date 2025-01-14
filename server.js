const express = require('express');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const dotenv = require('dotenv');
const cors = require('cors');

// Initialize dotenv and express
dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

// PostgreSQL Database Connection
const pool = new Pool({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});

// Signup Route
app.post('/api/signup', async (req, res) => {
  const { username, email, password, userType, pgLocation, distanceFromCollege } = req.body;

  // Store password in plain text (not recommended in production!)
  try {
    const result = await pool.query(
      'INSERT INTO users (username, email, password, user_type, pg_location, distance_from_college) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [username, email, password, userType, pgLocation || null, distanceFromCollege || null]
    );

    res.status(201).json({ message: 'Signup successful' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Server setup
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
