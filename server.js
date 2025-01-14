import express from 'express';
import pkg from 'pg';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pkg;
const app = express();
const port = process.env.PORT || 3001;

// PostgreSQL connection
const pool = new Pool({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_NAME,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT || 5432,
});

// Middleware to parse JSON request body
app.use(express.json());

// Utility functions
const hashPassword = (password, salt = crypto.randomBytes(16).toString('hex')) => {
  const hashedPassword = crypto
    .pbkdf2Sync(password, salt, 1000, 64, 'sha512')
    .toString('hex');
  return { hashedPassword, salt };
};

const verifyPassword = (password, salt, hashedPassword) => {
  const hashedInput = crypto
    .pbkdf2Sync(password, salt, 1000, 64, 'sha512')
    .toString('hex');
  return hashedInput === hashedPassword;
};

// Signup route
app.post('/api/signup', async (req, res) => {
  const { username, email, password, userType } = req.body;

  if (!username || !email || !password || !userType) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  try {
    // Check if the email already exists
    const emailCheckResult = await pool.query(
      'SELECT * FROM details WHERE email = $1',
      [email]
    );
    if (emailCheckResult.rows.length > 0) {
      return res.status(400).json({ message: 'Email is already registered.' });
    }

    // Hash the password
    const { hashedPassword, salt } = hashPassword(password);

    // Insert new user into the database
    const insertResult = await pool.query(
      'INSERT INTO details (username, email, password, salt, user_type) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [username, email, hashedPassword, salt, userType]
    );

    res.status(201).json({
      message: 'Signup successful!',
      userId: insertResult.rows[0].id,
    });
  } catch (err) {
    console.error('Error during signup:', err.message);
    res
      .status(500)
      .json({ message: 'An error occurred while signing up. Please try again.' });
  }
});

// Login route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  try {
    // Check if the user exists
    const userResult = await pool.query(
      'SELECT * FROM details WHERE email = $1',
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const user = userResult.rows[0];

    // Verify the password
    const isValidPassword = verifyPassword(password, user.salt, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    res.status(200).json({
      message: 'Login successful!',
      userId: user.id,
      username: user.username,
      userType: user.user_type,
    });
  } catch (err) {
    console.error('Error during login:', err.message);
    res
      .status(500)
      .json({ message: 'An error occurred while logging in. Please try again.' });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
