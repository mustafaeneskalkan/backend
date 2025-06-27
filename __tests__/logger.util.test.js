const logger = require('../utils/logger');
describe('Logger Utility', () => {
  it('should have http and error methods', () => {
    expect(typeof logger.http).toBe('function');
    expect(typeof logger.error).toBe('function');
  });

  it('should log without throwing', () => {
    expect(() => logger.http('test http')).not.toThrow();
    expect(() => logger.error('test error')).not.toThrow();
  });
});
