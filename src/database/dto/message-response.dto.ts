import { Expose } from 'class-transformer';
import { BaseResponseDto } from './base-response.dto';

/**
 * DTO for message response
 *
 * @export
 * @class MessageResponseDto
 */
export class MessageResponseDto extends BaseResponseDto {
  constructor(message: string);
  constructor(message: string, success: boolean);
  constructor(message: string, success?: boolean) {
    super();
    this.success = success ?? true;
    this.message = message;
  }

  @Expose()
  success: boolean;

  @Expose()
  message: string;
}
