const userController = require('../controller/user');
const User = require('../model/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

jest.mock('../model/user');
jest.mock('bcryptjs');
jest.mock('jsonwebtoken');

const logger = { http: jest.fn(), error: jest.fn() };
userController.__setLogger = (customLogger) => {
  userController.logger = customLogger;
};

const mockRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
};

describe('User Controller', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    userController.logger = logger;
  });

  describe('register', () => {
    it('should return 400 if required fields are missing', async () => {
      const req = { body: { email: '', password: '', username: '' } };
      const res = mockRes();
      await userController.register(req, res);
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ message: 'Email, username, and password are required' });
    });

    it('should return 400 if email already exists', async () => {
      User.findOne.mockImplementation(({ email }) => email ? { email } : null);
      const req = { body: { email: 'test@example.com', password: 'pass', username: 'user' } };
      const res = mockRes();
      await userController.register(req, res);
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ message: 'Email already exists' });
    });

    it('should return 400 if username already exists', async () => {
      User.findOne.mockImplementation(({ email, username }) => {
        if (email) return null;
        if (username) return { username };
        return null;
      });
      const req = { body: { email: 'test@example.com', password: 'pass', username: 'user' } };
      const res = mockRes();
      await userController.register(req, res);
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ message: 'Username already exists' });
    });

    it('should register user successfully', async () => {
      User.findOne.mockResolvedValue(null);
      bcrypt.hash.mockResolvedValue('hashed');
      User.mockImplementation(() => ({ save: jest.fn() }));
      const req = { body: { email: 'test@example.com', password: 'pass', username: 'user' } };
      const res = mockRes();
      await userController.register(req, res);
      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith({ message: 'User registered successfully' });
    });

    it('should handle server error', async () => {
      User.findOne.mockRejectedValue(new Error('fail'));
      const req = { body: { email: 'test@example.com', password: 'pass', username: 'user' } };
      const res = mockRes();
      await userController.register(req, res);
      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ message: 'Server error' });
    });
  });

  describe('login', () => {
    it('should return 400 if required fields are missing', async () => {
      const req = { body: { email: '', password: '' } };
      const res = mockRes();
      await userController.login(req, res);
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ message: 'Email and password are required' });
    });

    it('should return 400 if user not found', async () => {
      User.findOne.mockResolvedValue(null);
      const req = { body: { email: 'test@example.com', password: 'pass' } };
      const res = mockRes();
      await userController.login(req, res);
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ message: 'Invalid credentials' });
    });

    it('should return 400 if password does not match', async () => {
      User.findOne.mockResolvedValue({ password: 'hashed' });
      bcrypt.compare.mockResolvedValue(false);
      const req = { body: { email: 'test@example.com', password: 'wrong' } };
      const res = mockRes();
      await userController.login(req, res);
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ message: 'Invalid credentials' });
    });

    it('should login successfully', async () => {
      User.findOne.mockResolvedValue({ _id: 'id', password: 'hashed' });
      bcrypt.compare.mockResolvedValue(true);
      jwt.sign.mockReturnValue('token');
      process.env.JWT_SECRET = 'secret';
      const req = { body: { email: 'test@example.com', password: 'pass' } };
      const res = mockRes();
      await userController.login(req, res);
      expect(res.json).toHaveBeenCalledWith({ token: 'token' });
    });

    it('should handle server error', async () => {
      User.findOne.mockRejectedValue(new Error('fail'));
      const req = { body: { email: 'test@example.com', password: 'pass' } };
      const res = mockRes();
      await userController.login(req, res);
      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ message: 'Server error' });
    });

    it('should return 500 if JWT_SECRET is not set (login)', async () => {
      delete process.env.JWT_SECRET;
      User.findOne.mockResolvedValue({ _id: 'id', password: 'hashed' });
      bcrypt.compare.mockResolvedValue(true);
      const req = { body: { email: 'test@example.com', password: 'pass' } };
      const res = mockRes();
      await userController.login(req, res);
      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ message: 'Server error' });
    });
  });
});
