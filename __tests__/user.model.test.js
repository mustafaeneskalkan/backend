const mongoose = require('mongoose');
const User = require('../model/user');

describe('User Model', () => {
  it('should have required fields', () => {
    const schemaPaths = User.schema.paths;
    expect(schemaPaths).toHaveProperty('username');
    expect(schemaPaths).toHaveProperty('email');
    expect(schemaPaths).toHaveProperty('password');
    expect(schemaPaths).toHaveProperty('createdAt');
  });

  it('should require username, email, and password', () => {
    const user = new User();
    const error = user.validateSync();
    expect(error.errors).toHaveProperty('username');
    expect(error.errors).toHaveProperty('email');
    expect(error.errors).toHaveProperty('password');
  });

  it('should set createdAt by default', () => {
    const user = new User({ username: 'a', email: 'a@a.com', password: 'p' });
    expect(user.createdAt).toBeInstanceOf(Date);
  });
});
