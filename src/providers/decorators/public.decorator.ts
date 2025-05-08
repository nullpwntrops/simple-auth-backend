import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_ROUTE = 'isPublic';

/**
 * Decorator to mark a route as public.
 * This is used to indicate that the route does not require authentication.
 *
 * @returns {Function} The metadata function to set the public route flag.
 */
export const Public = () => SetMetadata(IS_PUBLIC_ROUTE, true);
