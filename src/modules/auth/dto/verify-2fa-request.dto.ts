import { IsEmail, IsString } from 'class-validator';

/**
 * Verify2FARequestDto class.  This is the body of the request.
 *
 * @export
 * @class Verify2FARequestDto
 */
export class Verify2FARequestDto {
  @IsString({ message: 'Username must be a string' })
  userName?: string;

  @IsEmail({}, { message: 'Please provide a valid email address' })
  email?: string;

  @IsString()
  code: string;
}
