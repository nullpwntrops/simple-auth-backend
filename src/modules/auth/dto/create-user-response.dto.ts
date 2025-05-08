import { Expose } from 'class-transformer';
import { BaseResponseDto } from '../../../database/dto/base-response.dto';
import { UserEntity } from '../../../database/entities/user.entity';

/**
 * Response DTO from creating a new user
 *
 * @export
 * @class CreateUserResponseDto
 * @extends {BaseResponseDto}
 */
export class CreateUserResponseDto extends BaseResponseDto {
  constructor(user: Partial<UserEntity>) {
    super();
    Object.assign(this, user);
  }

  @Expose()
  email: string;

  @Expose()
  userName: string;
}
