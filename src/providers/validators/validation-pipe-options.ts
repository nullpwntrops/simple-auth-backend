import { BadRequestException, ValidationError, ValidationPipeOptions } from '@nestjs/common';
import { getConfig } from '../../common/config/service-config';

export const validationPipeOptions = (): ValidationPipeOptions => {
  const config = getConfig().service;
  return {
    // Display extra debug messages to console when in DEV mode
    enableDebugMessages: config.isDevelopment,

    // Strip properties that are not in the DTO
    whitelist: true,

    // Keep validating after error only when in DEV mode
    stopAtFirstError: !config.isDevelopment,

    // Transform payloads to DTO instances
    transform: true,
    transformOptions: {
      enableImplicitConversion: true, // Allow basic type coercion
    },
    exceptionFactory: (validationErrors: ValidationError[] = []) => {
      const errors = validationErrors.map((error) => {
        const constraints = error.constraints ? Object.values(error.constraints) : [];
        return {
          property: error.property,
          message: constraints.length > 0 ? constraints[0] : 'Invalid value',
          constraints: constraints,
          value: error.value,
        };
      });

      return new BadRequestException({
        message: 'Validation failed',
        errors: errors,
      });
    },
  };
};
