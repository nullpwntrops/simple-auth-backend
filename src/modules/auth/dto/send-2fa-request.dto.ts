import { IsEmail, IsString } from 'class-validator';

/**
 * DTO for sending 2FA
 *
 * @export
 * @class Send2FARequestDto
 */
export class Send2FARequestDto {
  @IsString({ message: 'Username must be a string' })
  userName?: string;

  @IsEmail({}, { message: 'Please provide a valid email address' })
  email?: string;
}
