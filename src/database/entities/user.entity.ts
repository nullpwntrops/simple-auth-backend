import { Entity, Column } from 'typeorm';
import { Exclude } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';
import { BaseEntity } from './base.entity';
import { UserRoles } from '../../common/constants/enums';

/**
 * User entity class representing a user in the system.
 *
 * @export
 * @class UserEntity
 * @extends {BaseEntity}
 */
@Entity('users')
export class UserEntity extends BaseEntity {
  @ApiProperty({
    example: 'janedoe',
    description: 'Username for login and identification',
  })
  @Column({ unique: true, type: 'citext' })
  userName: string;

  @ApiProperty({
    example: 'jane_doe@example.com',
    description: 'Email address of the user',
  })
  @Column({ unique: true, type: 'citext' })
  email: string;

  @ApiProperty({
    example: 'Password123!',
    description: 'User password (hashed when stored)',
  })
  @Column({ type: 'text' })
  @Exclude()
  password: string;

  @ApiProperty({
    description: 'User role for authorization',
    enum: ['user', 'admin'],
    default: 'user',
  })
  @Column({
    type: 'enum',
    enum: UserRoles,
    default: UserRoles.USER,
  })
  role: UserRoles;

  @ApiProperty({
    description: 'Whether the user is verified or not',
    default: false,
  })
  @Column({ default: false, type: 'boolean' })
  isVerified: boolean;

  @ApiProperty({
    description: 'Timestamp of when the user was verified',
  })
  @Column({ type: 'timestamp', nullable: true })
  verifiedAt: Date;

  @ApiProperty({
    description: 'IP address from where the user was verified',
  })
  @Column({ type: 'inet', nullable: true })
  verifiedFromIp: string;

  @ApiProperty({
    description: 'Whether two-factor authentication is enabled or not',
    default: false,
  })
  @Column({ default: false, type: 'boolean' })
  enable2FA: boolean;

  @ApiProperty({
    description: 'Timestamp of when the user enabled 2FA',
  })
  @Column({ type: 'timestamp', nullable: true })
  enabled2FAAt: Date;

  @ApiProperty({
    description: 'IP address from where the user enabled 2FA',
  })
  @Column({ type: 'inet', nullable: true })
  enabled2FAFromIp: string;

  @Column({ default: false, type: 'boolean' })
  isLocked: boolean;

  @Column({ type: 'timestamp', nullable: true })
  isLockedExpiresAt: Date;

  @Column({ type: 'text', nullable: true })
  isLockedReason: string;

  @Column({ default: 0, type: 'int' })
  failedLoginAttempts: number;

  @Column({ type: 'timestamp', nullable: true })
  failedLoginAttemptsAt: Date;

  @Column({ type: 'inet', nullable: true })
  failedLoginAttemptsFromIp: string;

  @Column({ type: 'text', nullable: true })
  failedLoginAttemptsReason: string;

  @ApiProperty({
    description: 'Timestamp of the last successful login',
  })
  @Column({ type: 'timestamp', nullable: true })
  lastLogin: Date;

  @ApiProperty({
    description: 'IP address of the last successful login',
  })
  @Column({ type: 'inet', nullable: true })
  lastLoginIp: string;

  @ApiProperty({
    description: 'Timestamp of the last successful logout',
  })
  @Column({ type: 'timestamp', nullable: true })
  lastLogout: Date;

  @ApiProperty({
    description: 'IP address of the last successful logout',
  })
  @Column({ type: 'inet', nullable: true })
  lastLogoutIp: string;

  @ApiProperty({
    description: 'API key for accessing protected resources',
  })
  @Column({ type: 'text', nullable: true })
  apiKey: string;

  @ApiProperty({
    description: 'Access token (short term)',
  })
  @Column({ type: 'text', nullable: true })
  accessToken: string;

  @ApiProperty({
    description: 'Refresh token for obtaining a new access token',
  })
  @Column({ type: 'text', nullable: true })
  refreshToken: string;

  @ApiProperty({
    description: 'Password reset token',
  })
  @Column({ type: 'text', nullable: true })
  resetToken: string;

  @ApiProperty({
    description: 'Timestamp of when the reset token will expire',
  })
  @Column({ type: 'timestamp', nullable: true })
  resetTokenExpiresAt: Date;

  @ApiProperty({
    description: 'Verification token for email verification',
  })
  @Column({ type: 'text', nullable: true })
  verificationToken: string;

  @ApiProperty({
    description: 'Timestamp of when the verification token will expire',
  })
  @Column({ type: 'timestamp', nullable: true })
  verificationTokenExpiresAt: Date;

  @ApiProperty({
    description: 'Secret for two-factor authentication',
    required: false,
  })
  @Column({ type: 'text', nullable: true })
  twoFASecret: string;

  @ApiProperty({
    description: 'Timestamp of when the 2FA secret will expire',
  })
  @Column({ type: 'timestamp', nullable: true })
  twoFASecretExpiresAt: Date;
}
