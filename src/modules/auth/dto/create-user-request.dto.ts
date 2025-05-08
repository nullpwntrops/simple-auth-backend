import { PickType } from '@nestjs/mapped-types';
import { BaseUserDto } from '../../../database/dto/base-user.dto';

/**
 * DTO for creating a new user.
 *
 * @export
 * @class CreateUserRequestDto
 * @extends {PickType(BaseUserDto, ['email', 'userName', 'password'] as const)}
 */
export class CreateUserRequestDto extends PickType(BaseUserDto, ['email', 'userName', 'password'] as const) {}
