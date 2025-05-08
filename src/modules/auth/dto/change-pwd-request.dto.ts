import { ApiProperty } from '@nestjs/swagger';
import { IsStrongPassword } from 'class-validator';
import { PWD_MAX_LENGTH, PWD_MIN_LENGTH } from '../../../common/constants/constants';

/**
 * Change password request DTO
 *
 * @export
 * @class ChangePwdRequestDto
 */
export class ChangePwdRequestDto {
  @ApiProperty({
    example: 'StrongPassword123!',
    description: `User password (${PWD_MIN_LENGTH}-${PWD_MAX_LENGTH} characters)`,
  })
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
  oldPassword: string;

  @ApiProperty({
    example: 'StrongPassword123!',
    description: `User password (${PWD_MIN_LENGTH}-${PWD_MAX_LENGTH} characters)`,
  })
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
  newPassword: string;
}
