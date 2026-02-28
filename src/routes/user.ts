import express from 'express';
import UserController from '../controllers/user.js';
import { authenticateToken, authenticateRefreshToken, requireEmailVerification } from '../middleware/auth.js';
import { requireCsrf } from '../middleware/csrf.js';

const router = express.Router();

// CSRF double-submit protection (no-op for GET/HEAD/OPTIONS)
router.use(requireCsrf);

// Public routes (no authentication required)
router.post('/register', UserController.register.bind(UserController));
router.post('/login', UserController.login.bind(UserController));
router.post('/refresh-token', authenticateRefreshToken, UserController.refreshToken.bind(UserController));
router.post('/verify-email', UserController.verifyEmail.bind(UserController));
router.post('/verify-email-change', UserController.verifyEmailChange.bind(UserController));
router.post('/resend-verification', UserController.resendVerification.bind(UserController));

// Protected routes (authentication required)
router.post('/logout', authenticateToken, UserController.logout.bind(UserController));
router.post('/logout-all', authenticateToken, UserController.logoutAll.bind(UserController));
router.get('/session', authenticateToken, UserController.getSession.bind(UserController));
router.get('/sessions', authenticateToken, UserController.getSessions.bind(UserController));
router.delete('/sessions/:sessionId', authenticateToken, UserController.terminateSession.bind(UserController));

router.post('/change-email', authenticateToken, requireEmailVerification, UserController.changeEmail.bind(UserController));
router.post('/change-password', authenticateToken, UserController.changePassword.bind(UserController));
router.post('/request-password-change', UserController.requestPasswordReset.bind(UserController));
router.post('/reset-password', UserController.resetPassword.bind(UserController));


export default router;
