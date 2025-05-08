// base-response.dto.ts
import { Exclude, instanceToPlain } from 'class-transformer';

/**
 * BaseResponseDto is a base class for all response DTOs.
 * It provides a common structure and functionality for all response DTOs.
 *
 * @export
 * @abstract
 * @class BaseResponseDto
 */
@Exclude() // Exclude all properties by default
export abstract class BaseResponseDto {
  /**
   * Function to convert an instance object to plain JSON.
   *
   * By default, it excludes all properties except for those marked with
   * the `@Expose` decorator.
   *
   * Note: this function must be called before returning to caller.
   * Otherwise, sensitive data might be returned to client.
   *
   * @return {*} JSON object after transformation
   * @memberof BaseResponseDto
   */
  toJson(): any {
    return instanceToPlain(this, { excludeExtraneousValues: true });
  }
}
