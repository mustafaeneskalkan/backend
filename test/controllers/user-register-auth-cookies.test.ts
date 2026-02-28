import { jest } from '@jest/globals';

// Mock dependencies BEFORE importing the controller (ESM)
const mockUser = {
  _id: 'user-id-1',
  username: 'tester',
  email: 'tester@example.com',
  passwordChangedAt: new Date(),
  role: 'Writer',
  name: undefined,
  emailVerification: { emailVerified: false },
  lastLoginAt: undefined as unknown,
  setVerificationToken: jest.fn(async () => undefined),
  save: jest.fn(async () => undefined),
  comparePassword: jest.fn(async () => true),
};

const UserModel = {
  findOne: jest.fn(async () => null),
  create: jest.fn(async () => mockUser),
};

const SessionModel = {
  deleteMany: jest.fn(async () => ({ deletedCount: 0 })),
  find: jest.fn(() => ({
    sort: jest.fn(() => ({
      select: jest.fn(() => ({
        lean: jest.fn(async () => []),
      })),
    })),
  })),
  create: jest.fn(async () => undefined),
};

const sendMail = jest.fn(async () => undefined);

jest.unstable_mockModule('../../src/models/user.js', () => ({
  default: UserModel,
}));

jest.unstable_mockModule('../../src/models/session.js', () => ({
  default: SessionModel,
}));

jest.unstable_mockModule('../../src/utils/nodemailer.js', () => ({
  default: sendMail,
}));

describe('UserController.register', () => {
  beforeEach(() => {
    jest.clearAllMocks();

    process.env.JWT_EMAIL_VERIFY_SECRET = 'test-email-secret';
    process.env.FRONTEND_URL = 'http://localhost:3000';
    process.env.JWT_ACCESS_SECRET = 'test-access-secret';
    process.env.JWT_REFRESH_SECRET = 'test-refresh-secret';

    delete process.env.ACCESS_TOKEN_COOKIE_NAME;
    delete process.env.REFRESH_TOKEN_COOKIE_NAME;
    delete process.env.SESSION_ID_COOKIE_NAME;
  });

  it('sets the same auth/session cookies as login', async () => {
    const { ACCESS_TOKEN_COOKIE_NAME, REFRESH_TOKEN_COOKIE_NAME, SESSION_ID_COOKIE_NAME } =
      await import('../../src/utils/cookies.js');

    const controller = (await import('../../src/controllers/user.js')).default;

    const req: any = {
      body: {
        username: 'tester',
        email: 'tester@example.com',
        password: 'Password123!',
      },
      headers: { 'user-agent': 'jest' },
      ip: '127.0.0.1',
      connection: { remoteAddress: '127.0.0.1' },
    };

    const res: any = {
      cookie: jest.fn(),
      status: jest.fn(function status(this: any) {
        return this;
      }),
      json: jest.fn(function json(this: any) {
        return this;
      }),
    };

    const next = jest.fn();

    await controller.register(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(201);

    const payload = res.json.mock.calls[0]?.[0];
    expect(payload?.session?.sessionId).toEqual(expect.any(String));
    expect(payload?.session?.expiresIn).toBe(900);

    // Cookie names + paths must match login
    expect(res.cookie).toHaveBeenCalledWith(
      ACCESS_TOKEN_COOKIE_NAME,
      expect.any(String),
      expect.objectContaining({ httpOnly: true, path: '/' })
    );

    expect(res.cookie).toHaveBeenCalledWith(
      REFRESH_TOKEN_COOKIE_NAME,
      expect.any(String),
      expect.objectContaining({ httpOnly: true, path: '/api/users' })
    );

    expect(res.cookie).toHaveBeenCalledWith(
      SESSION_ID_COOKIE_NAME,
      payload.session.sessionId,
      expect.objectContaining({ httpOnly: true, path: '/api/users' })
    );

    expect(SessionModel.create).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: mockUser._id,
        sessionId: payload.session.sessionId,
        refreshTokenHash: expect.any(String),
        isActive: true,
      })
    );
  });
});
