import { SetMetadata } from '@nestjs/common';
import { UserRoles } from '../../common/constants/enums';

export const ROLES_KEY = 'roles';

/**
 * Roles decorator - define roles for a route
 * @param roles - array of roles
 * @returns {Function} - metadata function
 */
export const Roles = (...roles: UserRoles[]) => SetMetadata(ROLES_KEY, roles);
