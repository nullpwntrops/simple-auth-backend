import { SetMetadata } from '@nestjs/common';

export const IS_SEMI_PUBLIC_ROUTE = 'isSemiPublic';

/**
 * Semi-public decorator - mark routes as semi-public.
 *
 * Semi-public routes require authorization but do not require authentication
 * (e.g. a JWT token).  This is useful for routes that are accessible to both
 * authenticated and unauthenticated users, but still require authorization.
 * For example, a route that allows users to sign up for an account or login
 * with a password.
 *
 * @returns {Function} The metadata function to set the semi-public route flag.
 */
export const SemiPublic = () => SetMetadata(IS_SEMI_PUBLIC_ROUTE, true);
