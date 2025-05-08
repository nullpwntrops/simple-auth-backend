import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { InjectPinoLogger, Logger } from 'nestjs-pino';
import { Observable, map } from 'rxjs';
import { BaseResponseDto } from '../../database/dto/base-response.dto';

@Injectable()
export class ResponseInterceptor implements NestInterceptor {
  constructor(@InjectPinoLogger(ResponseInterceptor.name) private readonly logger: Logger) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      map((data) => {
        if (data instanceof BaseResponseDto) {
          // Data is extended from BaseResponseDto.  Call the 'toJson' function to ensure no data leaks.
          // TODO: Figure out how to add access and refresh tokens to valid responses.
          return data.toJson();
        }
        // Don't know what this is, just return it
        return data;
      }),
    );
  }
}
