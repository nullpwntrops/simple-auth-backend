/*
 * This file contains all the routes for the application.
 */

// Top level API route
export const TopRoute = 'api';

// Application routes
export enum AppRoutes {
  HELLO = 'hello',
  HEARTBEAT = 'heartbeat',
}

// Auth routes
export enum AuthRoutes {
  ROOT = 'auth',
  SIGNUP = 'signup',
  LOGIN = 'login',
  LOGOUT = 'logout',
  CHANGE_PASSWORD = 'change-password',
  REFRESH_TOKEN = 'refresh',
  VERIFY_EMAIL = 'verify-email',
  RESEND_VERIFICATION_EMAIL = 'resend-verification-email',
  ENABLE_2FA = 'enable-2fa',
  DISABLE_2FA = 'disable-2fa',
  VERIFY_2FA = 'verify-2fa',
  SEND_2FA = 'send-2fa',
}

// Health route
export enum HealthRoute {
  ROOT = 'health',
}
