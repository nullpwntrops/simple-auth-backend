import { UserEntity } from 'database/entities/user.entity';
import { UserRoles } from '../../common/constants/enums';

/**
 * Defines the actual data stored within the JWT payload.
 * This DTO represents the claims that identify the user and their session.
 * It should only contain the necessary information to identify and authorize
 * the user, plus standard JWT claims.
 *
 * @export
 * @class JwtPayloadDto
 */
export class JwtPayloadDto {
  constructor(user: UserEntity) {
    this.sub = user.id;
    this.email = user.email;
    this.userName = user.userName;
    this.apiKey = user.apiKey;
    this.role = user.role;
    this.isVerified = user.isVerified;
    this.enable2FA = user.enable2FA;
    this.createdAt = user.createdAt;
  }

  /**
   * Subject - The User ID. This is the primary identifier for the user.
   * Corresponds to `user.id` from the UserEntity.
   */
  sub: string;

  /**
   * User's email address.
   */
  email: string;

  /**
   * User's username.
   */
  userName: string;

  /**
   * API key associated with the user for this session.
   * This key is generated when tokens are created.
   */
  apiKey: string;

  /**
   * User's role, determining their access level.
   */
  role: UserRoles;

  /**
   * Indicates if the user's email address has been verified.
   */
  isVerified: boolean;

  /**
   * Indicates if the user has two-factor authentication enabled.
   */
  enable2FA: boolean;

  /**
   * Timestamp of when the user account was created.
   * Included from the UserEntity.
   */
  createdAt: Date;

  /**
   * IP address of the request.
   * Added by AuthGuard when the token is verified.
   */
  ip: string;

  /**
   * Request ID - Unique identifier for the request.
   * This is added by the AuthGuard when the token is verified.
   * It can be used to track the request across multiple services.
   */
  reqId: string;

  /**
   * Issued At - Standard JWT claim. Timestamp (seconds since epoch) when the token was issued.
   * This is automatically added by the JWT signing library.
   */
  iat: number;

  /**
   * Expiration Time - Standard JWT claim. Timestamp (seconds since epoch) when the token will expire.
   * This is automatically added by the JWT signing library.
   */
  exp: number;
}
