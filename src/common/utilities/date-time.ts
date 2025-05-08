import { DateTime, DurationLike } from 'luxon';

/**
 * Date-time utility functions.
 */

/**
 * Add an interval to either the current time or an input time.
 * Interval format is nnnx where nnn is a positive integer
 * and x is one of the following interval period.
 *    s: seconds
 *    m: minutes
 *    h: hours
 *    d: days
 * @param interval - Interval of time to add.
 * @param dateValue - Optional date value to add the interval to.
 * @returns - The new date value.
 */
export function addInterval(interval: string, dateValue = currentTimeStamp()): Date {
  const value = parseInt(interval.slice(0, -1));
  if (isNaN(value) || value <= 0) {
    throw new Error('Invalid interval value');
  }
  let duration: DurationLike;
  const intervalPeriod = interval.at(-1).toLowerCase();
  switch (intervalPeriod) {
    case 's':
      duration = { seconds: value };
      break;

    case 'm':
      duration = { minutes: value };
      break;

    case 'h':
      duration = { hours: value };
      break;

    case 'd':
      duration = { days: value };
      break;

    default:
      throw new Error('Invalid interval period');
  }
  const newDate = DateTime.fromJSDate(dateValue).plus(duration);
  return new Date(newDate.valueOf());
}

/**
 * Check if a date is expired.
 * @param expiry - The expiry date to check.
 * @returns - True if the date is expired, false otherwise.
 */
export function isExpired(expiry: Date): boolean {
  const now = currentTimeStamp();
  return expiry < now;
}

/**
 * Get the current time in milliseconds.
 * @returns - The current time in milliseconds.
 */
export function currentTimeStamp(): Date {
  return new Date(DateTime.now().valueOf());
}
