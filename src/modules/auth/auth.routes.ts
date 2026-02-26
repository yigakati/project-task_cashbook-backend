import { Router } from 'express';
import { container } from 'tsyringe';
import { AuthController } from './auth.controller';
import { validate } from '../../middlewares/validate';
import { authenticate } from '../../middlewares/authenticate';
import { authRateLimiter, otpRateLimiter } from '../../middlewares/rateLimiter';
import {
    registerSchema,
    loginSchema,
    changePasswordSchema,
    verifyEmailSchema,
    resendVerificationSchema,
    forgotPasswordSchema,
    resetPasswordSchema,
    googleLoginSchema,
} from './auth.dto';

const router = Router();
const authController = container.resolve(AuthController);

// Public routes
router.post(
    '/register',
    authRateLimiter,
    validate(registerSchema),
    authController.register.bind(authController) as any
);

router.post(
    '/login',
    authRateLimiter,
    validate(loginSchema),
    authController.login.bind(authController) as any
);

router.post(
    '/refresh',
    authRateLimiter,
    authController.refresh.bind(authController) as any
);

// Google OAuth
router.post(
    '/google',
    authRateLimiter,
    validate(googleLoginSchema),
    authController.googleLogin.bind(authController) as any
);

// Email verification
router.post(
    '/verify-email',
    authRateLimiter,
    validate(verifyEmailSchema),
    authController.verifyEmail.bind(authController) as any
);

router.post(
    '/resend-verification',
    otpRateLimiter,
    validate(resendVerificationSchema),
    authController.resendVerification.bind(authController) as any
);

// Forgot / reset password
router.post(
    '/forgot-password',
    otpRateLimiter,
    validate(forgotPasswordSchema),
    authController.forgotPassword.bind(authController) as any
);

router.post(
    '/reset-password',
    authRateLimiter,
    validate(resetPasswordSchema),
    authController.resetPassword.bind(authController) as any
);

// Protected routes
router.post(
    '/logout',
    authenticate as any,
    authController.logout.bind(authController) as any
);

router.post(
    '/logout-all',
    authenticate as any,
    authController.logoutAll.bind(authController) as any
);

router.post(
    '/change-password',
    authenticate as any,
    validate(changePasswordSchema),
    authController.changePassword.bind(authController) as any
);

router.get(
    '/login-history',
    authenticate as any,
    authController.getLoginHistory.bind(authController) as any
);

export default router;
