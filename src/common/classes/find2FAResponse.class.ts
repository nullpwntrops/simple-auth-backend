import { TwoFARouteType } from '../../common/constants/enums';
import { UserEntity } from '../../database/entities/user.entity';

export class find2FAUserResponse {
  constructor(user: UserEntity, routeType: TwoFARouteType) {
    this.user = user;
    this.routeType = routeType;
  }

  user: UserEntity;

  routeType: TwoFARouteType;
}
