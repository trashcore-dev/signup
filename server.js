// server.js
const express = require('express');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(cors());

// Rate limiting
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: 'Too many OTP requests, please try again later'
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 login requests per windowMs
  message: 'Too many login attempts, please try again later'
});

// In-memory storage (use database in production)
let users = [];
let otpStore = new Map(); // {email: {code, expires, attempts}}
let emailBlacklist = new Set(); // Permanently registered emails
let passwordResetTokens = new Map(); // {token: {email, expires}}

// Email transporter configuration
const transporter = nodemailer.createTransporter({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'trashcoreclient@gmail.com',
    pass: process.env.EMAIL_PASS || 'your_app_password_here'
  }
});

// Helper function to generate random string
function generateRandomString(length) {
  return crypto.randomBytes(length).toString('hex');
}

// Routes
app.post('/api/register', otpLimiter, async (req, res) => {
  try {
    const { email, username, password } = req.body;

    // Validation
    if (!email || !username || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if email is permanently registered
    if (emailBlacklist.has(email)) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Check if username already exists
    const existingUser = users.find(u => u.username === username);
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Validate password strength
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + 10 * 60 * 1000; // 10 minutes

    // Store OTP temporarily
    otpStore.set(email, {
      code: otp,
      expires: expires,
      attempts: 0,
      username: username,
      password: password // Will be hashed after verification
    });

    // Send OTP email
    const mailOptions = {
      from: process.env.EMAIL_USER || 'trashcoreclient@gmail.com',
      to: email,
      subject: 'Verify Your Account - Bot Deployer',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #38bdf8;">Verify Your Account</h2>
          <p>Hello ${username},</p>
          <p>Thank you for registering. Please use the following verification code to complete your registration:</p>
          <div style="background: #f8fafc; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
            <h1 style="font-size: 32px; color: #38bdf8; letter-spacing: 10px;">${otp}</h1>
          </div>
          <p>This code will expire in 10 minutes.</p>
          <p>If you didn't request this, please ignore this email.</p>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);

    res.json({ 
      message: 'Verification code sent successfully',
      email: email
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/verify', async (req, res) => {
  try {
    const { email, otp, username, password } = req.body;

    if (!email || !otp || !username || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const otpData = otpStore.get(email);

    if (!otpData) {
      return res.status(400).json({ error: 'No verification code found for this email' });
    }

    if (Date.now() > otpData.expires) {
      otpStore.delete(email);
      return res.status(400).json({ error: 'Verification code has expired' });
    }

    if (otpData.attempts >= 3) {
      otpStore.delete(email);
      return res.status(400).json({ error: 'Too many failed attempts. Please request a new code.' });
    }

    if (otpData.code !== otp) {
      otpData.attempts += 1;
      otpStore.set(email, otpData);
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    // Check if email is already registered (double-check)
    if (emailBlacklist.has(email)) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const newUser = {
      id: Date.now().toString(),
      email: email,
      username: username,
      password: hashedPassword,
      verified: true,
      createdAt: new Date().toISOString(),
      lastLogin: null,
      resetTokens: [] // Store password reset tokens
    };

    users.push(newUser);

    // Add email to permanent blacklist
    emailBlacklist.add(email);

    // Remove OTP
    otpStore.delete(email);

    res.json({ 
      message: 'Account verified successfully',
      user: { email: newUser.email, username: newUser.username }
    });

  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = users.find(u => u.email === email);

    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    if (!user.verified) {
      return res.status(400).json({ error: 'Please verify your email first' });
    }

    // Update last login
    user.lastLogin = new Date().toISOString();

    res.json({
      message: 'Login successful',
      user: { email: user.email, username: user.username }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Password reset request
app.post('/api/forgot-password', otpLimiter, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const user = users.find(u => u.email === email);

    if (!user) {
      // Don't reveal if email exists - for security
      return res.json({ message: 'If email exists, reset instructions sent' });
    }

    // Generate reset token
    const resetToken = generateRandomString(32);
    const expires = Date.now() + 1 * 60 * 60 * 1000; // 1 hour

    passwordResetTokens.set(resetToken, {
      email: email,
      expires: expires
    });

    // Send reset email
    const resetUrl = `${req.get('host')}/reset-password/${resetToken}`;
    const mailOptions = {
      from: process.env.EMAIL_USER || 'trashcoreclient@gmail.com',
      to: email,
      subject: 'Password Reset Request - Bot Deployer',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #fbbf24;">Password Reset</h2>
          <p>Hello,</p>
          <p>You requested to reset your password. Click the link below to reset it:</p>
          <div style="text-align: center; margin: 20px 0;">
            <a href="${resetUrl}" style="background: #38bdf8; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
              Reset Password
            </a>
          </div>
          <p>This link will expire in 1 hour.</p>
          <p>If you didn't request this, please ignore this email.</p>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);

    res.json({ message: 'If email exists, reset instructions sent' });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Reset password with token
app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token and new password are required' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    const resetData = passwordResetTokens.get(token);

    if (!resetData) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    if (Date.now() > resetData.expires) {
      passwordResetTokens.delete(token);
      return res.status(400).json({ error: 'Reset token has expired' });
    }

    const user = users.find(u => u.email === resetData.email);

    if (!user) {
      passwordResetTokens.delete(token);
      return res.status(400).json({ error: 'User not found' });
    }

    // Hash new password
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    // Update user password
    user.password = hashedNewPassword;

    // Add to reset history
    if (!user.resetTokens) user.resetTokens = [];
    user.resetTokens.push({
      token: token,
      timestamp: new Date().toISOString()
    });

    // Clear reset token
    passwordResetTokens.delete(token);

    res.json({ message: 'Password reset successfully' });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
