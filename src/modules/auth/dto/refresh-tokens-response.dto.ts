import { Expose } from 'class-transformer';
import { Tokens } from '../../../common/types/global-types';
import { BaseResponseDto } from '../../../database/dto/base-response.dto';

/**
 * RefreshTokenResponseDto class.
 *
 * @export
 * @class RefreshTokenResponseDto
 */
export class RefreshTokensResponseDto extends BaseResponseDto {
  constructor(tokens: Tokens) {
    super();
    this.accessToken = tokens.accessToken;
    this.refreshToken = tokens.refreshToken;
  }
  @Expose()
  accessToken: string;

  @Expose()
  refreshToken: string;
}
