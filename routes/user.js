const express = require('express');
const router = express.Router();
const userController = require('../controller/user');
const rateLimit = require('express-rate-limit');

const authLimiter = rateLimit({
  windowMs: 3 * 60 * 1000, // 3 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  message: 'Too many requests, please try again later.'
});

router.post('/register', authLimiter, userController.register);
router.post('/login', authLimiter, userController.login);

module.exports = router;
