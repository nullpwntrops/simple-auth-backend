import { PartialType } from '@nestjs/mapped-types';
import { CreateUserRequestDto } from './create-user-request.dto';

/**
 * Login request DTO
 *
 * @export
 * @class LoginRequestDto
 * @extends {PartialType(CreateUserRequestDto)}
 */
export class LoginRequestDto extends PartialType(CreateUserRequestDto) {}
