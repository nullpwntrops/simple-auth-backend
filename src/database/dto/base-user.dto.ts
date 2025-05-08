import {
  IsBoolean,
  IsDate,
  IsEmail,
  IsEnum,
  IsInt,
  IsIP,
  IsNotEmpty,
  IsPositive,
  IsString,
  IsStrongPassword,
  IsUUID,
} from 'class-validator';
import { UserRoles } from '../../common/constants/enums';

/**
 * Class that defines the whole User object.  This is essentially the
 * same as the User entity object.  The difference is that this
 * class is annotated using Swagger and validation decorators instead
 * of TypeORM.
 *
 * @export
 * @class BaseUserDto
 */
export class BaseUserDto {
  @IsUUID()
  id: string;

  @IsNotEmpty({ message: 'Username is required' })
  @IsString({ message: 'Username must be a string' })
  userName: string;

  @IsNotEmpty({ message: 'Email is required' })
  @IsEmail({}, { message: 'Please provide a valid email address' })
  email: string;

  @IsNotEmpty({ message: 'Password is required' })
  @IsStrongPassword(
    {
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1,
    },
    {
      message: `Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character`,
    },
  )
  password: string;

  @IsEnum(UserRoles, { message: 'Invalid user role' })
  role: UserRoles;

  @IsBoolean({ message: 'Must be a boolean value' })
  isVerified: boolean;

  @IsDate()
  verifiedAt: Date;

  @IsIP()
  verifiedFromIp: string;

  @IsBoolean({ message: 'Must be a boolean value' })
  enable2FA: boolean;

  @IsDate()
  enabled2FAAt: Date;

  @IsIP()
  enabled2FAFromIp: string;

  @IsBoolean({ message: 'Must be a boolean value' })
  isLocked: boolean;

  @IsDate()
  isLockedExpiresAt: Date;

  @IsString()
  isLockedReason: string;

  @IsPositive({ message: 'Must be a positive number' })
  @IsInt({ message: 'Must be an integer' })
  failedLoginAttempts: number;

  @IsDate()
  failedLoginAttemptsAt: Date;

  @IsIP()
  failedLoginAttemptsFromIp: string;

  @IsString()
  failedLoginAttemptsReason: string;

  @IsDate()
  lastLogin: Date;

  @IsIP()
  lastLoginIp: string;

  @IsDate()
  lastLogout: Date;

  @IsIP()
  lastLogoutIp: string;

  @IsString()
  apiKey: string;

  @IsString()
  accessToken: string;

  @IsString()
  refreshToken: string;

  @IsString()
  resetToken: string;

  @IsDate()
  resetTokenExpiresAt: Date;

  @IsString()
  verificationToken: string;

  @IsDate()
  verificationTokenExpiresAt: Date;

  @IsString()
  twoFASecret: string;

  @IsDate()
  twoFASecretExpiresAt: Date;

  @IsDate()
  createdAt: Date;

  @IsDate()
  updatedAt: Date;
}
