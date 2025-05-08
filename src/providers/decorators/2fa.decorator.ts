import { SetMetadata } from '@nestjs/common';

export const IS_2FA_ROUTE = 'is2fa';

/**
 * Decorator to mark a route as public.
 * This is used to indicate that the route does not require authentication.
 *
 * @returns {Function} The metadata function to set the public route flag.
 */
export const Is2FA = () => SetMetadata(IS_2FA_ROUTE, true);
