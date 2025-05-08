import * as Joi from 'joi';
import { Config, Enums } from '../constants';
import { JOI_EXPIRATION_REGEX } from '../constants/config-constants';

/**
 * Configuration schema used to validate the environment variables.
 * Used by the getConfig() function.
 */
export const serviceConfigSchema = Joi.object({
  // Application settings
  service: Joi.object({
    // TODO: Should this have a default value?  Or should it fail if it's not defined?
    nodeEnv: Joi.string()
      .valid(
        <string>Enums.NodeEnv.DEVELOPMENT,
        <string>Enums.NodeEnv.PRODUCTION,
        <string>Enums.NodeEnv.TEST,
        <string>Enums.NodeEnv.SANDBOX,
        <string>Enums.NodeEnv.STAGING,
      )
      .required()
      .default(<string>Enums.NodeEnv.DEVELOPMENT),
    serviceName: Joi.string().required(),
    identifier: Joi.string().required(),
    serviceUrl: Joi.string().required(),
    port: Joi.number().integer().greater(0).default(Config.DEFAULT_PORT),
    dockerPort: Joi.number().integer().greater(0).default(Config.DEFAULT_DOCKER_PORT),
    app_name: Joi.string().required(),
    api_key: Joi.string().required(),
    isDevelopment: Joi.boolean(),
    isTest: Joi.boolean(),
    isProduction: Joi.boolean(),
  }),

  // Database settings
  database: Joi.object({
    host: Joi.string().required(),
    database: Joi.string().required(),
    port: Joi.number().integer().greater(0).default(Config.DEFAULT_DB_PORT),
    username: Joi.string().required(),
    password: Joi.string().required(),
    sslmode: Joi.boolean().default(false),
    logging: Joi.boolean().default(false),
    sync: Joi.boolean().default(false),
  }),

  // JWT settings
  jwt: Joi.object({
    accessSecret: Joi.string().required(),
    accessExpiration: Joi.string()
      .pattern(JOI_EXPIRATION_REGEX)
      .required()
      .default(Config.DEFAULT_JWT_ACCESS_EXPIRATION),
    refreshSecret: Joi.string().required(),
    refreshExpiration: Joi.string()
      .pattern(JOI_EXPIRATION_REGEX)
      .required()
      .default(Config.DEFAULT_JWT_REFRESH_EXPIRATION),
    resetExpiration: Joi.string().pattern(JOI_EXPIRATION_REGEX).required().default(Config.DEFAULT_JWT_RESET_EXPIRATION),
    verifyExpiration: Joi.string()
      .pattern(JOI_EXPIRATION_REGEX)
      .required()
      .default(Config.DEFAULT_JWT_VERIFY_EXPIRATION),
  }),

  // Misc application settings
  misc: Joi.object({
    twoFaLength: Joi.number().integer().greater(2).default(Config.DEFAULT_2FA_LENGTH),
    twoFaExpiration: Joi.string().pattern(JOI_EXPIRATION_REGEX).required().default(Config.DEFAULT_2FA_EXPIRATION),
    maxFailAttempts: Joi.number().integer().greater(0).default(Config.DEFAULT_MAX_FAIL_ATTEMPTS),
    lockoutExpiration: Joi.string().pattern(JOI_EXPIRATION_REGEX).required().default(Config.DEFAULT_LOCKOUT_EXPIRATION),
    healthMemory: Joi.number().integer().greater(0).default(Config.DEFAULT_HEALTH_MEMORY),
    healthDiskThreshold: Joi.number().greater(0).default(Config.DEFAULT_HEALTH_DISK_THRESHOLD),
    pinoLogLevel: Joi.string()
      .valid(
        <string>Enums.PinoLogLevels.FATAL,
        <string>Enums.PinoLogLevels.ERROR,
        <string>Enums.PinoLogLevels.WARN,
        <string>Enums.PinoLogLevels.INFO,
        <string>Enums.PinoLogLevels.DEBUG,
        <string>Enums.PinoLogLevels.TRACE,
        <string>Enums.PinoLogLevels.SILENT,
      )
      .default(<string>Config.DEFAULT_PINO_LOG_LEVEL),
  }),

  // Throttler settings
  throttler: Joi.object({
    ttl: Joi.number().integer().greater(0).default(Config.DEFAULT_THROTTLE_TTL),
    limit: Joi.number().integer().greater(0).default(Config.DEFAULT_THROTTLE_LIMIT),
  }),

  // Mail settings
  mail: Joi.object({
    from: Joi.string().email().required(),
    transportOptions: Joi.object({
      host: Joi.string().required(),
      port: Joi.number().integer().greater(0).default(Config.DEFAULT_MAIL_PORT),
      auth: Joi.object({
        user: Joi.string().required(),
        pass: Joi.string().required(),
      }),
    }),
  }),

  // Swagger settings
  swagger: Joi.object({
    enabled: Joi.boolean().default(false),
  }),
});
