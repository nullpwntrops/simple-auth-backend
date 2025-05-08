import * as Joi from 'joi';
import { Config, Enums } from '../constants';
import { JOI_EXPIRATION_REGEX } from 'common/constants/config-constants';

/**
 * Configuration schema used to validate the .env variables.
 * Used by the ConfigModule.
 */
export const configSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid(
      <string>Enums.NodeEnv.DEVELOPMENT,
      <string>Enums.NodeEnv.PRODUCTION,
      <string>Enums.NodeEnv.TEST,
      <string>Enums.NodeEnv.SANDBOX,
      <string>Enums.NodeEnv.STAGING,
    )
    .default(<string>Enums.NodeEnv.DEVELOPMENT),
  PORT: Joi.number().integer().greater(0).default(Config.DEFAULT_PORT),
  DOCKER_PORT: Joi.number().integer().greater(0).default(Config.DEFAULT_DOCKER_PORT),
  SERVICE_NAME: Joi.string().required(),
  SERVICE_IDENTIFIER: Joi.string().required(),
  SERVICE_URL: Joi.string().required(),
  APP_NAME: Joi.string().required(),
  API_KEY: Joi.string().required(),
  DB_HOST: Joi.string().required(),
  DB_DATABASE: Joi.string().required(),
  DB_PORT: Joi.number().integer().greater(0).default(Config.DEFAULT_DB_PORT),
  DB_USERNAME: Joi.string().required(),
  DB_PASSWORD: Joi.string().required(),
  DB_LOGGING: Joi.boolean().default(false),
  DB_SSLMODE: Joi.boolean().default(false),
  DB_SYNC: Joi.boolean().default(false),
  JWT_ACCESS_SECRET: Joi.string().required(),
  JWT_ACCESS_EXPIRATION: Joi.string()
    .pattern(JOI_EXPIRATION_REGEX)
    .required()
    .default(Config.DEFAULT_JWT_ACCESS_EXPIRATION),
  JWT_REFRESH_SECRET: Joi.string().required(),
  JWT_REFRESH_EXPIRATION: Joi.string()
    .pattern(JOI_EXPIRATION_REGEX)
    .required()
    .default(Config.DEFAULT_JWT_REFRESH_EXPIRATION),
  JWT_RESET_EXPIRATION: Joi.string()
    .pattern(JOI_EXPIRATION_REGEX)
    .required()
    .default(Config.DEFAULT_JWT_RESET_EXPIRATION),
  JWT_VERIFY_EXPIRATION: Joi.string()
    .pattern(JOI_EXPIRATION_REGEX)
    .required()
    .default(Config.DEFAULT_JWT_VERIFY_EXPIRATION),
  TWO_FA_LENGTH: Joi.number().integer().greater(2).default(Config.DEFAULT_2FA_LENGTH),
  TWO_FA_EXPIRATION: Joi.string().pattern(JOI_EXPIRATION_REGEX).required().default(Config.DEFAULT_2FA_EXPIRATION),
  MAX_FAIL_ATTEMPTS: Joi.number().integer().greater(5).default(Config.DEFAULT_MAX_FAIL_ATTEMPTS),
  LOCKOUT_EXPIRATION: Joi.string().pattern(JOI_EXPIRATION_REGEX).required().default(Config.DEFAULT_LOCKOUT_EXPIRATION),
  HEALTH_MEMORY: Joi.number().integer().greater(0).default(Config.DEFAULT_HEALTH_MEMORY),
  HEALTH_DISK_THRESHOLD: Joi.number().greater(0).default(Config.HEALTH_DISK_THRESHOLD),
  PINO_LOG_LEVEL: Joi.string()
    .valid(
      <string>Enums.PinoLogLevels.DEBUG,
      <string>Enums.PinoLogLevels.ERROR,
      <string>Enums.PinoLogLevels.FATAL,
      <string>Enums.PinoLogLevels.INFO,
      <string>Enums.PinoLogLevels.SILENT,
      <string>Enums.PinoLogLevels.TRACE,
      <string>Enums.PinoLogLevels.WARN,
    )
    .default(<string>Config.DEFAULT_PINO_LOG_LEVEL),
  THROTTLE_TTL: Joi.number().integer().greater(50).default(Config.DEFAULT_THROTTLE_TTL),
  THROTTLE_LIMIT: Joi.number().integer().greater(5).default(Config.DEFAULT_THROTTLE_LIMIT),
  MAIL_FROM: Joi.string().email().required(),
  MAIL_HOST: Joi.string().required(),
  MAIL_PORT: Joi.number().integer().greater(0).default(Config.DEFAULT_MAIL_PORT),
  MAIL_AUTH_USER: Joi.string().required(),
  MAIL_AUTH_PASS: Joi.string().required(),
  SWAGGER_ENABLED: Joi.boolean().default(false),
});
