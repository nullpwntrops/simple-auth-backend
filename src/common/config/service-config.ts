import { InternalServerErrorException } from '@nestjs/common';
import { RequiredEnvironmentVariableMissingError } from '../exceptions';
import { Config, Enums } from '../constants';
import { isDevelopment, isProduction, isTest, isTrue } from '../utilities/utilities';
import { serviceConfigSchema } from './service-config.validation';

/**
 * Configuration settings for the application.
 * Values are loaded from environment variables with sensible defaults.
 */
export const getConfig = (): AppConfig => {
  const envConfig = {
    // Application settings
    service: {
      nodeEnv: (process.env.NODE_ENV?.toLowerCase() as Enums.NodeEnv) || Config.DEFAULT_NODE_ENV,
      serviceName: requireEnvVar(Config.SERVICE_NAME),
      identifier: requireEnvVar(Config.SERVICE_IDENTIFIER),
      serviceUrl: requireEnvVar(Config.SERVICE_URL),
      port: toPositiveInteger(Config.PORT, Config.DEFAULT_PORT),
      dockerPort: toPositiveInteger(Config.DOCKER_PORT, Config.DEFAULT_DOCKER_PORT),
      app_name: requireEnvVar(Config.APP_NAME),
      api_key: requireEnvVar(Config.API_KEY),
      isDevelopment: isDevelopment(),
      isTest: isTest(),
      isProduction: isProduction(),
    },

    // Database settings
    database: {
      host: requireEnvVar(Config.DB_HOST),
      database: requireEnvVar(Config.DB_DATABASE),
      port: toPositiveInteger(Config.DB_PORT, Config.DEFAULT_DB_PORT),
      username: requireEnvVar(Config.DB_USERNAME),
      password: requireEnvVar(Config.DB_PASSWORD),
      sslmode: toBoolean(Config.DB_SSLMODE),
      logging: toBoolean(Config.DB_LOGGING) || isDevelopment(),
      sync: toBoolean(Config.DB_SYNC) || isDevelopment(),
    },

    // JWT settings
    jwt: {
      accessSecret: requireEnvVar(Config.JWT_ACCESS_SECRET),
      accessExpiration: process.env.JWT_ACCESS_EXPIRATION ?? Config.DEFAULT_JWT_ACCESS_EXPIRATION,
      refreshSecret: requireEnvVar(Config.JWT_REFRESH_SECRET),
      refreshExpiration: process.env.JWT_REFRESH_EXPIRATION ?? Config.DEFAULT_JWT_REFRESH_EXPIRATION,
      resetExpiration: process.env.JWT_RESET_EXPIRATION ?? Config.DEFAULT_JWT_RESET_EXPIRATION,
      verifyExpiration: process.env.JWT_VERIFY_EXPIRATION ?? Config.DEFAULT_JWT_VERIFY_EXPIRATION,
    },

    // Misc settings
    misc: {
      twoFaLength: toPositiveInteger(Config.TWO_FA_LENGTH, Config.DEFAULT_2FA_LENGTH, 2),
      twoFaExpiration: process.env.JWT_2FA_EXPIRATION ?? Config.DEFAULT_2FA_EXPIRATION,
      maxFailAttempts: toPositiveInteger(Config.MAX_FAIL_ATTEMPTS, Config.DEFAULT_MAX_FAIL_ATTEMPTS),
      lockoutExpiration: process.env.JWT_LOCKOUT_EXPIRATION ?? Config.DEFAULT_LOCKOUT_EXPIRATION,
      healthMemory: toPositiveInteger(process.env.HEALTH_MEMORY, Config.DEFAULT_HEALTH_MEMORY),
      healthDiskThreshold: toPositiveNumber(process.env.HEALTH_DISK_THRESHOLD, Config.DEFAULT_HEALTH_DISK_THRESHOLD),
      pinoLogLevel: (process.env.PINO_LOG_LEVEL.toLowerCase() as Enums.PinoLogLevels) || Config.DEFAULT_PINO_LOG_LEVEL,
    },

    // Throttling settings
    throttler: {
      ttl: toPositiveInteger(Config.THROTTLE_TTL, Config.DEFAULT_THROTTLE_TTL),
      limit: toPositiveInteger(Config.THROTTLE_LIMIT, Config.DEFAULT_THROTTLE_LIMIT),
    },

    // Mail settings
    mail: {
      from: requireEnvVar(Config.MAIL_FROM),
      transportOptions: {
        host: requireEnvVar(Config.MAIL_HOST),
        port: toPositiveInteger(Config.MAIL_PORT, Config.DEFAULT_MAIL_PORT),
        auth: {
          user: requireEnvVar(Config.MAIL_AUTH_USER),
          pass: requireEnvVar(Config.MAIL_AUTH_PASS),
        },
      },
    },

    // Swagger settings
    swagger: {
      enabled: isTrue(Config.SWAGGER_ENABLED) || isDevelopment(),
    },
  };
  const { error } = serviceConfigSchema.validate(envConfig);
  if (error) {
    throw new InternalServerErrorException(`Joi validation error: ${error.message}`);
  }
  return envConfig;
};

//**************************************
//#region Configuration Interface
//**************************************

export interface AppConfig {
  service: ServiceConfig;
  database: DbConfig;
  jwt: JwtConfig;
  misc: MiscConfig;
  throttler: ThrottlerConfig;
  mail: MailConfig;
  swagger: SwaggerConfig;
}

export interface ServiceConfig {
  nodeEnv: Enums.NodeEnv;
  serviceName: string;
  identifier: string;
  serviceUrl: string;
  port: number;
  dockerPort: number;
  app_name: string;
  api_key: string;
  isDevelopment: boolean;
  isTest: boolean;
  isProduction: boolean;
}
export interface DbConfig {
  host: string;
  database: string;
  port: number;
  username: string;
  password: string;
  sslmode: boolean;
  logging: boolean;
  sync: boolean;
}

export interface JwtConfig {
  accessSecret: string;
  accessExpiration: string;
  refreshSecret: string;
  refreshExpiration: string;
  resetExpiration: string;
  verifyExpiration: string;
}

export interface MiscConfig {
  twoFaLength: number;
  twoFaExpiration: string;
  maxFailAttempts: number;
  lockoutExpiration: string;
  healthMemory: number;
  healthDiskThreshold: number;
  pinoLogLevel: Enums.PinoLogLevels;
}

export interface ThrottlerConfig {
  ttl: number;
  limit: number;
}

export interface MailConfig {
  from: string;
  transportOptions: {
    host: string;
    port: number;
    auth: {
      user: string;
      pass: string;
    };
  };
}

export interface SwaggerConfig {
  enabled: boolean;
}

//#endregion
//**************************************

//**************************************
//#region Local support functions
//**************************************

/**
 * Function to read an environment variable and return
 * a positive integer (> 0).
 * @param name - Name of variable to read.
 * @param defaultValue - Default value to use if negative or zero.
 * @returns - Return the value of the environment variable or the default value.
 */
function toPositiveInteger(name: string, defaultValue: number, greaterThan: number = 0): number {
  const value = process.env[name];
  if (!value) {
    return defaultValue;
  }
  const parsedValue = parseInt(value);
  if (isNaN(parsedValue) || parsedValue <= greaterThan) {
    return defaultValue;
  }
  return parsedValue;
}

function toPositiveNumber(name: string, defaultValue: number, greaterThan: number = 0): number {
  const value = process.env[name];
  if (!value) {
    return defaultValue;
  }
  const parsedValue = parseFloat(value);
  if (isNaN(parsedValue) || parsedValue <= greaterThan) {
    return defaultValue;
  }
  return parsedValue;
}

/**
 * Make sure the environment variable exists and return its value.
 * Throw an error if it doesn't exist.
 * @param name - Name of the environment variable to read.
 * @returns - Return the value of the environment variable.
 */
function requireEnvVar(name: string): string {
  const envVar: string | undefined = process.env[name];
  if (!envVar || envVar === '') {
    throw new RequiredEnvironmentVariableMissingError(name);
  }
  return envVar;
}

/**
 * Read the environment variable and convert to a boolean value.
 * If the environment variable is not set, it will throw an error.
 * Any case combination of 'true' will return true, everything
 * else will return false.
 * @param name - Name of the environment variable to read.
 * @returns - Return the boolean value of the environment variable.
 */
function toBoolean(name: string): boolean {
  const value = requireEnvVar(name);
  return value.toLocaleLowerCase() === <string>Enums.BooleanEnum.TRUE;
}

//#endregion
//**************************************
