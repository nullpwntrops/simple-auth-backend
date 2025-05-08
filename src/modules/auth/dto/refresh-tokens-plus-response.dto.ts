import { Expose } from 'class-transformer';
import { BaseResponseDto } from '../../../database/dto/base-response.dto';
import { RefreshTokensPlusResponseOptions } from '../../../common/interfaces/refresh-token-plus.interface';

/**
 * DTO object for refreshing tokens as well as passing some messages back to client.
 *
 * @export
 * @class RefreshTokensPlusResponseDto
 */
export class RefreshTokensPlusResponseDto extends BaseResponseDto {
  constructor(options: RefreshTokensPlusResponseOptions) {
    super();
    this.message = options.message;
    this.success = options.success ?? true; // Default success flag = true
    this.accessToken = options.tokens?.accessToken ?? undefined;
    this.refreshToken = options.tokens?.refreshToken ?? undefined;
  }

  @Expose()
  message: string;

  @Expose()
  success: boolean;

  @Expose()
  accessToken: string;

  @Expose()
  refreshToken: string;
}
