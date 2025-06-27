jest.mock('mongoose', () => ({ connect: jest.fn() }));
const mongoose = require('mongoose');
const logger = require('../utils/logger');
const connectDB = require('../config/db');

describe('DB Config', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should connect to MongoDB and log success', async () => {
    mongoose.connect.mockResolvedValue();
    logger.info = jest.fn();
    await connectDB();
    expect(mongoose.connect).toHaveBeenCalled();
    expect(logger.info).toHaveBeenCalledWith('MongoDB connected');
  });

  it('should log error and exit on failure', async () => {
    const exitSpy = jest.spyOn(process, 'exit').mockImplementation(() => {});
    mongoose.connect.mockRejectedValue(new Error('fail'));
    logger.error = jest.fn();
    await connectDB();
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('MongoDB connection error:'));
    expect(exitSpy).toHaveBeenCalledWith(1);
    exitSpy.mockRestore();
  });
});
