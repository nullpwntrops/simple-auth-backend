import { MigrationInterface, QueryRunner } from 'typeorm';

export class InitialSchema1745770107664 implements MigrationInterface {
  name = 'InitialSchema1745770107664';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "users" (
        "id" UUID PRIMARY KEY,
        "userName" character varying NOT NULL UNIQUE,
        "email" character varying NOT NULL UNIQUE,
        "password" character varying NOT NULL,
        "role" character varying DEFAULT 'user' NOT NULL,
        "isVerified" boolean DEFAULT false NOT NULL,
        "verifiedAt" TIMESTAMP,
        "verifiedFromIp" inet,
        "enable2fa" boolean DEFAULT false NOT NULL,
        "enabled2FAAt" TIMESTAMP,
        "enabled2FAFromIp" inet,
        "lastLogin" TIMESTAMP,
        "lastLoginIp" inet,
        "lastLogout" TIMESTAMP,
        "lastLogoutIp" inet,
        "lastLoginAttempt" TIMESTAMP,
        "lastLoginAttemptIp" inet,
        "lastLoginAttemptReason" character varying,
        "apiKey" character varying,
        "accessToken" character varying,
        "refreshToken" character varying,
        "resetToken" character varying,
        "resetTokenExpiresAt" TIMESTAMP,
        "verificationToken" character varying,
        "verificationTokenExpiresAt TIMESTAMP,
        "twoFASecret" character varying,
        "twoFASecretExpiresAt" TIMESTAMP,
        "createdAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        "updatedAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS "users"`);
  }
}
