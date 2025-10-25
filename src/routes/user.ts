import express from 'express';
import csurf from 'csurf';
import UserController from '../controllers/user.js';
import { authenticateToken, authenticateRefreshToken } from '../middleware/auth.js';

const router = express.Router();

// CSRF middleware for modifying requests
const csrfProtection = csurf({
  cookie: { httpOnly: true, sameSite: 'lax' },
  value: (req: express.Request) => {
    return (req.headers['x-xsrf-token'] as string) || (req.body && req.body._csrf) || req.query._csrf;
  }
});

// Public routes (no authentication required)
router.post('/register', csrfProtection, UserController.register.bind(UserController));
router.post('/login', csrfProtection, UserController.login.bind(UserController));
router.post('/refresh-token', csrfProtection, authenticateRefreshToken, UserController.refreshToken.bind(UserController));
router.post('/verify-email', csrfProtection, UserController.verifyEmail.bind(UserController));
router.post('/resend-verification', csrfProtection, UserController.resendVerification.bind(UserController));

// Protected routes (authentication required)
router.post('/logout', csrfProtection, authenticateToken, UserController.logout.bind(UserController));
router.post('/logout-all', csrfProtection, authenticateToken, UserController.logoutAll.bind(UserController));
router.get('/session', authenticateToken, UserController.getSession.bind(UserController));
router.get('/sessions', authenticateToken, UserController.getSessions.bind(UserController));
router.delete('/sessions/:sessionId', csrfProtection, authenticateToken, UserController.terminateSession.bind(UserController));

router.post('/change-email', csrfProtection, authenticateToken, UserController.changeEmail.bind(UserController));
//router.post('/change-password', csrfProtection, authenticateToken, UserController.changePassword.bind(UserController));
//router.post('/request-password-change', csrfProtection, UserController.requestPasswordReset.bind(UserController));
//router.post('/reset-password', csrfProtection, UserController.resetPassword.bind(UserController));


export default router;
