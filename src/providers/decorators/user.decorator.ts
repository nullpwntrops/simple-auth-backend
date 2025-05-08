import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * User decorator - used to get the user object from the request.
 *
 * @param data Optional parameter to get a specific property from the user object.
 * @returns The user object or a specific property of the user object.
 */
export const User = createParamDecorator((data: string | undefined, ctx: ExecutionContext) => {
  try {
    const request = ctx.switchToHttp().getRequest();
    if (data) {
      return request.user[data];
    }
    return request.user;
  } catch {
    return null;
  }
});
