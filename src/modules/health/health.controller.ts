import { Controller, Get } from '@nestjs/common';
import {
  DiskHealthIndicator,
  HealthCheck,
  HealthCheckService,
  MemoryHealthIndicator,
  TypeOrmHealthIndicator,
} from '@nestjs/terminus';
import { UserRoles } from '../../common/constants/enums';
import { HealthRoute } from '../../common/constants/routes';
import { getConfig } from '../../common/config/service-config';
import { Roles } from '../../providers/decorators/roles.decorator';

@Controller(HealthRoute.ROOT)
export class HealthController {
  //*****************************
  //#region Constructors
  //*****************************

  constructor(
    private readonly health: HealthCheckService,
    private readonly db: TypeOrmHealthIndicator,
    private readonly disk: DiskHealthIndicator,
    private readonly memory: MemoryHealthIndicator,
  ) {}

  //#endregion
  //*****************************

  //*****************************
  //#region Public Methods
  //*****************************

  /**
   *  Health check endpoint.
   *
   * @return {*}
   * @memberof HealthController
   */
  @Get()
  @HealthCheck()
  @Roles(UserRoles.USER) // TODO: Change this to admin when deploying to production
  public healthCheck() {
    const config = getConfig();
    return this.health.check([
      () => this.db.pingCheck('db'),
      () => this.disk.checkStorage('storage', { path: '/', thresholdPercent: config.misc.healthDiskThreshold }),
      () => this.memory.checkHeap('memory_heap', 1024 * 1024 * config.misc.healthMemory),
    ]);
  }

  //#endregion
  //*****************************
}
