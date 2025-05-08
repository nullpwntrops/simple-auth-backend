export enum BooleanEnum {
  TRUE = 'true',
  FALSE = 'false',
}

export enum NodeEnv {
  DEVELOPMENT = 'development',
  TEST = 'test',
  SANDBOX = 'sandbox',
  STAGING = 'staging',
  PRODUCTION = 'production',
}

export enum UserRoles {
  ADMIN = 'admin',
  USER = 'user',
}

export enum TokenType {
  ACCESS_TOKEN,
  REFRESH_TOKEN,
  RESET_TOKEN,
  VERIFY_TOKEN,
  TWO_FA_TOKEN,
}

// Pino Log levels determine what type of logs will be
// displayed.  A level of 'info' means all logs below
// will be suppressed.  The following log levels are
// in descending order.
export enum PinoLogLevels {
  FATAL = 'fatal',
  ERROR = 'error',
  WARN = 'warn',
  INFO = 'info', // Usually set for production
  DEBUG = 'debug', // Usually set for dev
  TRACE = 'trace',
  SILENT = 'silent',
}

export enum TwoFARouteType {
  LOGIN, // This is for Login or enable 2FA
  PASSWORD, // This is used for Forget Password or Reset Password
}
