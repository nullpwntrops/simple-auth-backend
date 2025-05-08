import { HttpException, HttpStatus } from '@nestjs/common';

export class RequiredEnvironmentVariableMissingError extends HttpException {
  constructor(name: string) {
    super(`Required environment variable is missing {${name}}.`, HttpStatus.INTERNAL_SERVER_ERROR);
  }
}
