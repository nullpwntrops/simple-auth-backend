/**
 * Password related constants.
 */
export const PWD_MIN_LENGTH = 8;
export const PWD_MAX_LENGTH = 50;
export const PWD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,50}$/;
export const PWD_REGEX_ERROR_MESSAGE =
  'Password must contain at least one uppercase letter, one lowercase letter, and one number';
