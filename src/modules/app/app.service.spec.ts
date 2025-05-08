import { Test, TestingModule } from '@nestjs/testing';
import { PinoLogger } from 'nestjs-pino';
// Import DateTime from luxon for type annotations; its runtime behavior will be mocked.
import { DateTime } from 'luxon'; 
import { v4 as uuid4 } from 'uuid';
import { AppConfig, getConfig } from '../../common/config/service-config';
import { UserRoles } from '../../common/constants/enums';
import { JwtPayloadDto } from '../../database/dto/jwt-payload.dto';
import { MessageResponseDto } from '../../database/dto/message-response.dto';
import { AppService } from './app.service';

// Mock getConfig before it's imported by the service
jest.mock('../../common/config/service-config', () => ({
  getConfig: jest.fn(),
}));

// 1. Get the actual Luxon library before it's mocked
const actualLuxon = jest.requireActual('luxon');
// 2. Create a fixed DateTime instance that our mock will return.
//    Using a specific ISO string and UTC ensures consistency across test environments.
const fixedMockDateTimeInstance = actualLuxon.DateTime.fromISO('2023-10-27T10:30:00.000Z', { zone: 'utc' });

jest.mock('luxon', () => {
  const originalLuxon = jest.requireActual('luxon');
  return {
    ...originalLuxon, // Spread all exports from original luxon (Info, Duration, etc.)
    DateTime: {
      ...originalLuxon.DateTime, // Spread all static members of original DateTime (e.g., DATETIME_SHORT_WITH_SECONDS)
      local: jest.fn(() => fixedMockDateTimeInstance), // Mock DateTime.local() to return our fixed instance
    },
  };
});

const mockProcessUptime = jest.fn();
Object.defineProperty(process, 'uptime', {
  value: mockProcessUptime,
});

const mockLogger = {
  setContext: jest.fn(),
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
  trace: jest.fn(),
};

const mockUserPayload: JwtPayloadDto = {
  sub: 'user-id-xyz',
  email: 'verbose@example.com',
  userName: 'VerboseUser',
  apiKey: 'api-key-xyz',
  role: UserRoles.ADMIN,
  isVerified: true,
  enable2FA: true,
  createdAt: new Date('2022-01-01T00:00:00.000Z'),
  ip: '192.168.1.1',
  reqId: uuid4(),
  iat: Math.floor(Date.now() / 1000) - 1000,
  exp: Math.floor(Date.now() / 1000) + 3600,
};

const mockAppConfig: Partial<AppConfig> = {
  service: {
    serviceName: 'MyAwesomeService',
    nodeEnv: 'development',
    // Add other properties from ServiceConfig if they are used or needed for type compatibility
  } as any, // Using 'as any' to simplify mock if not all properties are needed for this test
};

describe('AppService', () => {
  let service: AppService;

  beforeEach(async () => {
    jest.clearAllMocks(); // Clear mocks at the beginning
    // Reset getConfig mock for each test
    (getConfig as jest.Mock).mockReturnValue(mockAppConfig);
    mockProcessUptime.mockReturnValue(300); // 5 minutes uptime
    const module: TestingModule = await Test.createTestingModule({
      providers: [AppService, { provide: PinoLogger, useValue: mockLogger }],
    }).compile();

    service = module.get<AppService>(AppService);
    (getConfig as jest.Mock).mockReturnValue(mockAppConfig); // Ensure config is mocked for constructor
    mockProcessUptime.mockReturnValue(300); // Reset uptime mock
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
    expect(mockLogger.setContext).toHaveBeenCalledWith(AppService.name);
  });

  describe('getHello', () => {
    it('should return "Hello World!" when verbose is false', () => {
      const result = service.getHello(false);
      expect(result).toBeInstanceOf(MessageResponseDto);
      expect(result.message).toBe('Hello World!');
      expect(getConfig).not.toHaveBeenCalled();
    });

    it('should return a detailed message when verbose is true', () => {
      const result = service.getHello(true, mockUserPayload);
      // Use the fixedMockDateTimeInstance for assertions.
      // DateTime.DATETIME_SHORT_WITH_SECONDS comes from the (mocked) DateTime static properties.
      const expectedTime = fixedMockDateTimeInstance.toLocaleString(DateTime.DATETIME_SHORT_WITH_SECONDS);
      const expectedUptimeMinutes = Math.floor(300 / 60); // 5

      expect(result).toBeInstanceOf(MessageResponseDto);
      expect(getConfig).toHaveBeenCalledTimes(1); // Called once inside getHello
      expect(DateTime.local).toHaveBeenCalledTimes(1); // Verifies the mocked DateTime.local was called
      expect(mockProcessUptime).toHaveBeenCalledTimes(1);
      expect(result.message).toContain(
        `Hello ${mockUserPayload.userName} from the ${mockAppConfig.service.serviceName} application!`,
      );
      expect(result.message).toContain(`Currently running in ${mockAppConfig.service.nodeEnv} mode.`);
      expect(result.message).toContain(`The system time is ${expectedTime}`);
      expect(result.message).toContain(`App uptime is ${expectedUptimeMinutes} minutes.`);
    });

    it('should return a detailed message with "Guest" if verbose is true and user is undefined', () => {
      const result = service.getHello(true, undefined); // Call with undefined user
      const expectedTime = fixedMockDateTimeInstance.toLocaleString(DateTime.DATETIME_SHORT_WITH_SECONDS);
      const expectedUptimeMinutes = Math.floor(300 / 60); // 5

      expect(result).toBeInstanceOf(MessageResponseDto);
      expect(getConfig).toHaveBeenCalledTimes(1);
      expect(DateTime.local).toHaveBeenCalledTimes(1);
      expect(mockProcessUptime).toHaveBeenCalledTimes(1);
      expect(result.message).toContain(
        `Hello Guest from the ${mockAppConfig.service.serviceName} application!`, // Check for "Guest"
      );
      expect(result.message).toContain(`Currently running in ${mockAppConfig.service.nodeEnv} mode.`);
      expect(result.message).toContain(`The system time is ${expectedTime}`);
      expect(result.message).toContain(`App uptime is ${expectedUptimeMinutes} minutes.`);
    });
  });
});
