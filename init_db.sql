\connect auth_db;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users(
  id UUID PRIMARY KEY DEFAULT public.uuid_generate_v4(),
  userName TEXT NOT NULL,
  email TEXT NOT NULL,
  password TEXT,
  role TEXT DEFAULT 'user' NOT NULL,
  isVerified BOOLEAN DEFAULT false NOT NULL,
  verifiedAt timestamp with time zone,
  verifiedFromIp inet,
  enable2FA BOOLEAN DEFAULT false NOT NULL,
  enabled2FAAt timestamp with time zone,
  enabled2FAFromIp inet,
  isLocked BOOLEAN DEFAULT false NOT NULL,
  isLockedExpiresAt timestamp with time zone,
  isLockedReason TEXT,
  failedLoginAttempts INT DEFAULT 0 NOT NULL,
  failedLoginAttemptsAt timestamp with time zone,
  failedLoginAttemptsFromIp inet,
  failedLoginAttemptsReason TEXT,
  lastLogin timestamp with time zone,
  lastLoginIp inet,
  lastLogout timestamp with time zone,
  lastLogoutIp inet,
  apiKey TEXT,
  accessToken TEXT,
  refreshToken TEXT,
  resetToken TEXT,
  resetTokenExpiresAt timestamp with time zone,
  verificationToken TEXT,
  verificationTokenExpiresAt timestamp with time zone,
  twoFASecret TEXT,
  twoFASecretExpiresAt timestamp with time zone,
  createdAt timestamp with time zone DEFAULT now() NOT NULL,
  updatedAt timestamp with time zone DEFAULT now() NOT NULL
);
