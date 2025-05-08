import { Enums } from '../constants';

/**
 * Check if the current environment is development.
 *
 * @returns - True if the current environment is development, false otherwise
 */
export function isDevelopment(): boolean {
  const value = process.env.NODE_ENV ?? <string>Enums.NodeEnv.DEVELOPMENT;
  return value === <string>Enums.NodeEnv.DEVELOPMENT;
}

/**
 * Check if the current environment is production.
 *
 * @returns - True if the current environment is production, false otherwise
 */
export function isProduction(): boolean {
  const value = process.env.NODE_ENV ?? <string>Enums.NodeEnv.PRODUCTION;
  return value === <string>Enums.NodeEnv.PRODUCTION;
}

/**
 * Check if the current environment is test.
 *
 * @returns - True if the current environment is test, false otherwise
 */
export function isTest(): boolean {
  const value = process.env.NODE_ENV ?? <string>Enums.NodeEnv.TEST;
  return value === <string>Enums.NodeEnv.TEST;
}

/**
 * Check if the given environment variable is true.
 * If the environment variable is not set, it will return false.
 * Any case combination of 'true' will return true, everything else will return false.
 *
 * @param name - Name of the environment variable to read.
 * @returns - Return the boolean value of the environment variable.
 */
export function isTrue(name: string): boolean {
  const value = process.env[name] ?? <string>Enums.BooleanEnum.FALSE;
  return value.toLocaleLowerCase() === <string>Enums.BooleanEnum.TRUE;
}
