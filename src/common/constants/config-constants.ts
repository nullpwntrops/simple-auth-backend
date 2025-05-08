import { NodeEnv, PinoLogLevels } from './enums';

/**************************************
 * Environment configuration key names
 **************************************/

// Application settings
export const NODE_ENV = 'NODE_ENV';
export const PORT = 'PORT';
export const DOCKER_PORT = 'DOCKER_PORT';
export const SERVICE_NAME = 'SERVICE_NAME';
export const SERVICE_IDENTIFIER = 'SERVICE_IDENTIFIER';
export const SERVICE_URL = 'SERVICE_URL';
export const APP_NAME = 'APP_NAME';
export const API_KEY = 'API_KEY';

// Database settings
export const DB_HOST = 'DB_HOST';
export const DB_DATABASE = 'DB_DATABASE';
export const DB_USERNAME = 'DB_USERNAME';
export const DB_PASSWORD = 'DB_PASSWORD';
export const DB_PORT = 'DB_PORT';
export const DB_LOGGING = 'DB_LOGGING';
export const DB_SSLMODE = 'DB_SSLMODE';
export const DB_SYNC = 'DB_SYNC';

// JWT settings
export const JWT_ACCESS_SECRET = 'JWT_ACCESS_SECRET';
export const JWT_ACCESS_EXPIRATION = 'JWT_ACCESS_EXPIRATION';
export const JWT_REFRESH_SECRET = 'JWT_REFRESH_SECRET';
export const JWT_REFRESH_EXPIRATION = 'JWT_REFRESH_EXPIRATION';
export const JWT_RESET_EXPIRATION = 'JWT_RESET_EXPIRATION';
export const JWT_VERIFY_EXPIRATION = 'JWT_VERIFY_EXPIRATION';

// Misc settings
export const TWO_FA_LENGTH = 'TWO_FA_LENGTH';
export const TWO_FA_EXPIRATION = 'TWO_FA_EXPIRATION';
export const MAX_FAIL_ATTEMPTS = 'MAX_FAIL_ATTEMPTS';
export const LOCKOUT_EXPIRATION = 'LOCKOUT_EXPIRATION';
export const HEALTH_MEMORY = 'HEALTH_MEMORY';
export const HEALTH_DISK_THRESHOLD = 'HEALTH_DISK_THRESHOLD';
export const PINO_LOG_LEVEL = 'PINO_LOG_LEVEL';

// Throttling settings
export const THROTTLE_TTL = 'THROTTLE_TTL';
export const THROTTLE_LIMIT = 'THROTTLE_LIMIT';

// Mail settings
export const MAIL_FROM = 'MAIL_FROM';
export const MAIL_HOST = 'MAIL_HOST';
export const MAIL_PORT = 'MAIL_PORT';
export const MAIL_AUTH_USER = 'MAIL_AUTH_USER';
export const MAIL_AUTH_PASS = 'MAIL_AUTH_PASS';

// Swagger settings
export const SWAGGER_ENABLED = 'SWAGGER_ENABLED';

/************************************************
 * Default values for some environment variables
 ************************************************/

// Default application settings
export const DEFAULT_NODE_ENV = NodeEnv.DEVELOPMENT;
export const DEFAULT_PORT = 3000;
export const DEFAULT_DOCKER_PORT = 2000;

// Default DB settings
export const DB_TYPE = 'postgres';
export const DEFAULT_DB_HOST = 'host.docker.internal';
export const DEFAULT_DB_PORT = 5432;

// Default Throttle settings
export const DEFAULT_THROTTLE_TTL = 60;
export const DEFAULT_THROTTLE_LIMIT = 10;

// Default JWT settings
export const DEFAULT_JWT_ACCESS_EXPIRATION = '1d';
export const DEFAULT_JWT_REFRESH_EXPIRATION = '7d';
export const DEFAULT_JWT_RESET_EXPIRATION = '30m';
export const DEFAULT_JWT_VERIFY_EXPIRATION = '1d';

// Default settings for Misc fields
export const DEFAULT_2FA_LENGTH = 4;
export const DEFAULT_2FA_EXPIRATION = '5m';
export const DEFAULT_MAX_FAIL_ATTEMPTS = 10;
export const DEFAULT_LOCKOUT_EXPIRATION = '5m';
export const DEFAULT_HEALTH_DISK_THRESHOLD = 0.75;
export const DEFAULT_HEALTH_MEMORY = 150;
export const DEFAULT_PINO_LOG_LEVEL = PinoLogLevels.INFO;

// Default Mail settings
export const DEFAULT_MAIL_PORT = 1025;

export const JOI_EXPIRATION_REGEX = /^\d{1,}[smhd]$/i;
