const User = require('../model/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');

function getJwtSecret() {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET is not defined in environment variables');
  }
  return process.env.JWT_SECRET;
}

exports.register = async (req, res) => {
  try {
    let { username, email, password } = req.body;
    if (!email || !password || !username) {
      logger.http('Register failed: Missing required fields');
      return res.status(400).json({ message: 'Email, username, and password are required' });
    }
    email = email.toLowerCase();
    logger.http(`Register attempt for email: ${email}, username: ${username}`);
    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      logger.http(`Register failed: Email already exists (${email})`);
      return res.status(400).json({ message: 'Email already exists' });
    }
    const existingUsername = await User.findOne({ username });
    if (existingUsername) {
      logger.http(`Register failed: Username already exists (${username})`);
      return res.status(400).json({ message: 'Username already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();
    logger.http(`User registered successfully: ${username} (${email})`);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    logger.error(`Register error: ${err}`);
    res.status(500).json({ message: 'Server error' });
  }
};

exports.login = async (req, res) => {
  try {
    let { email, password } = req.body;
    if (!email || !password) {
      logger.http('Login failed: Missing email or password');
      return res.status(400).json({ message: 'Email and password are required' });
    }
    email = email.toLowerCase();
    logger.http(`Login attempt for email: ${email}`);
    const user = await User.findOne({ email });
    if (!user) {
      logger.http(`Login failed: User with email: ${email} can not be found`);
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      logger.http(`Login failed: Invalid credentials for email: ${email}`);
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user._id }, getJwtSecret(), { expiresIn: '14d' });
    logger.http(`Login successful for email: ${email}`);
    res.json({ token });
  } catch (err) {
    logger.error(`Login error: ${err}`);
    res.status(500).json({ message: 'Server error' });
  }
};
