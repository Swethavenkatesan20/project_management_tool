const User = require('../models/user');
const bcrypt = require('bcryptjs');
const jsonwebtoken = require('jsonwebtoken');

// Register User
exports.register = async (req, res) => {
  const { password } = req.body;
  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user with hashed password
    req.body.password = hashedPassword;
    const user = await User.create(req.body);

    // Generate JWT token
    const token = jsonwebtoken.sign(
      { id: user._id },
      process.env.TOKEN_SECRET_KEY,
      { expiresIn: '24h' }
    );

    // Remove password before sending the response
    user.password = undefined;

    res.status(201).json({ user, token });
  } catch (err) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

// Login User
exports.login = async (req, res) => {
  const { username, password } = req.body;
  try {
    // Find user by username
    const user = await User.findOne({ username }).select('password username');
    if (!user) {
      return res.status(401).json({
        errors: [{ param: 'username', msg: 'Invalid username or password' }],
      });
    }

    // Compare the hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        errors: [{ param: 'password', msg: 'Invalid username or password' }],
      });
    }

    // Remove password from user object
    user.password = undefined;

    // Generate JWT token
    const token = jsonwebtoken.sign(
      { id: user._id },
      process.env.TOKEN_SECRET_KEY,
      { expiresIn: '24h' }
    );

    res.status(200).json({ user, token });
  } catch (err) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
};
