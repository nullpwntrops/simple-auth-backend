import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException } from '@nestjs/common';
import { PinoLogger } from 'nestjs-pino';
import { v4 as uuid4 } from 'uuid';
import { UserRoles } from '../../common/constants/enums';
import { Tokens } from '../../common/types/global-types';
import { JwtPayloadDto } from '../../database/dto/jwt-payload.dto';
import { MessageResponseDto } from '../../database/dto/message-response.dto';
import { CreateUserRequestDto } from './dto/create-user-request.dto';
import { LoginRequestDto } from './dto/login-request.dto';
import { ChangePwdRequestDto } from './dto/change-pwd-request.dto';
import { Verify2FARequestDto } from './dto/verify-2fa-request.dto';
import { Send2FARequestDto } from './dto/send-2fa-request.dto';
import { CreateUserResponseDto } from './dto/create-user-response.dto';
import { RefreshTokensResponseDto } from './dto/refresh-tokens-response.dto';
import { RefreshTokensPlusResponseDto } from './dto/refresh-tokens-plus-response.dto';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

const mockAuthService = {
  signUp: jest.fn(),
  login: jest.fn(),
  logout: jest.fn(),
  refreshToken: jest.fn(),
  changePassword: jest.fn(),
  resendVerification: jest.fn(),
  enable2FA: jest.fn(),
  disable2FA: jest.fn(),
  verify2FA: jest.fn(),
  send2FA: jest.fn(),
};

const mockLogger = {
  setContext: jest.fn(),
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
  trace: jest.fn(),
};

const mockUserPayload: JwtPayloadDto = {
  sub: 'user-id-123',
  email: 'test@example.com',
  userName: 'testuser',
  apiKey: 'api-key-123',
  role: UserRoles.USER,
  isVerified: true,
  enable2FA: false,
  createdAt: new Date('2023-01-01T00:00:00.000Z'),
  ip: '127.0.0.1',
  //reqId: '12345678-abcd-42d3-a456-123456789abc',
  reqId: uuid4(),
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
};

const mockTokens: Tokens = {
  accessToken: 'mockAccessToken',
  refreshToken: 'mockRefreshToken',
  apiKey: 'mockApiKey',
};

describe('AuthController', () => {
  let controller: AuthController;
  let authService: AuthService;

  beforeEach(async () => {
    jest.clearAllMocks(); // Clear mocks before each test
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        { provide: AuthService, useValue: mockAuthService },
        { provide: PinoLogger, useValue: mockLogger },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    authService = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
    expect(mockLogger.setContext).toHaveBeenCalledWith(AuthController.name);
  });

  describe('signUp', () => {
    it('should call authService.signUp and return its result', async () => {
      const createUserDto: CreateUserRequestDto = {
        email: 'test@example.com',
        userName: 'testuser',
        password: 'password@123',
      };
      const expectedResult = new CreateUserResponseDto({
        id: '1',
        email: 'test@example.com',
        userName: 'testuser',
        role: UserRoles.USER,
        isVerified: false,
        enable2FA: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      mockAuthService.signUp.mockResolvedValue(expectedResult);

      const result = await controller.signUp(createUserDto);

      expect(authService.signUp).toHaveBeenCalledWith(createUserDto);
      expect(result).toEqual(expectedResult);
    });
  });

  describe('login', () => {
    const ip = '127.0.0.1';
    it('should call authService.login and return its result when email is provided', async () => {
      const loginDto: LoginRequestDto = { email: 'test@example.com', password: 'password@123' };
      const expectedResult = new RefreshTokensResponseDto(mockTokens);
      mockAuthService.login.mockResolvedValue(expectedResult);

      const result = await controller.login(ip, loginDto);

      expect(authService.login).toHaveBeenCalledWith(loginDto, ip);
      expect(result).toEqual(expectedResult);
    });

    it('should call authService.login and return its result when userName is provided', async () => {
      const loginDto: LoginRequestDto = { userName: 'testuser', password: 'password@123' };
      const expectedResult = new RefreshTokensPlusResponseDto({ message: '2FA required', tokens: mockTokens });
      mockAuthService.login.mockResolvedValue(expectedResult);

      const result = await controller.login(ip, loginDto);

      expect(authService.login).toHaveBeenCalledWith(loginDto, ip);
      expect(result).toEqual(expectedResult);
    });

    it('should throw BadRequestException if no email or username is provided', async () => {
      const loginDto: LoginRequestDto = { password: 'password' };
      await expect(controller.login(ip, loginDto)).rejects.toThrow(BadRequestException);
      await expect(controller.login(ip, loginDto)).rejects.toThrow('Username or email must be specified.');
      expect(authService.login).not.toHaveBeenCalled();
    });
  });

  describe('send2FA', () => {
    it('should call authService.send2FA and return its result when email is provided', async () => {
      const send2FADto: Send2FARequestDto = { email: 'test@example.com' };
      const expectedResult = new MessageResponseDto('2FA code sent successfully.', true);
      mockAuthService.send2FA.mockResolvedValue(expectedResult);

      const result = await controller.send2FA(send2FADto);

      expect(authService.send2FA).toHaveBeenCalledWith(send2FADto);
      expect(result).toEqual(expectedResult);
    });

    it('should call authService.send2FA and return its result when userName is provided', async () => {
      const send2FADto: Send2FARequestDto = { userName: 'testuser' };
      const expectedResult = new MessageResponseDto('2FA code sent successfully.', true);
      mockAuthService.send2FA.mockResolvedValue(expectedResult);

      const result = await controller.send2FA(send2FADto);

      expect(authService.send2FA).toHaveBeenCalledWith(send2FADto);
      expect(result).toEqual(expectedResult);
    });

    it('should throw BadRequestException if no email or username is provided', async () => {
      const send2FADto: Send2FARequestDto = {}; // Empty DTO, neither email nor userName
      await expect(controller.send2FA(send2FADto)).rejects.toThrow(BadRequestException);
      await expect(controller.send2FA(send2FADto)).rejects.toThrow('Username or email must be specified.');
      expect(authService.send2FA).not.toHaveBeenCalled();
    });
  });


  describe('logout', () => {
    it('should call authService.logout and return its result', async () => {
      const expectedResult = new MessageResponseDto('Logout successful');
      mockAuthService.logout.mockResolvedValue(expectedResult);

      const result = await controller.logout(mockUserPayload);

      expect(authService.logout).toHaveBeenCalledWith(mockUserPayload);
      expect(result).toEqual(expectedResult);
    });
  });

  describe('refreshToken', () => {
    it('should call authService.refreshToken and return its result', async () => {
      const expectedResult = new RefreshTokensResponseDto(mockTokens);
      mockAuthService.refreshToken.mockResolvedValue(expectedResult);

      const result = await controller.refreshToken(mockUserPayload);

      expect(authService.refreshToken).toHaveBeenCalledWith(mockUserPayload);
      expect(result).toEqual(expectedResult);
    });
  });

  describe('changePassword', () => {
    it('should call authService.changePassword and return its result', async () => {
      const changePwdDto: ChangePwdRequestDto = { oldPassword: 'oldPassword', newPassword: 'newPassword' };
      const expectedResult = new RefreshTokensPlusResponseDto({ message: 'Password changed', tokens: mockTokens });
      mockAuthService.changePassword.mockResolvedValue(expectedResult);

      const result = await controller.changePassword(mockUserPayload, changePwdDto);

      expect(authService.changePassword).toHaveBeenCalledWith(mockUserPayload, changePwdDto);
      expect(result).toEqual(expectedResult);
    });
  });

  describe('resendVerificationEmail', () => {
    it('should call authService.resendVerification and return its result', async () => {
      const expectedResult = new RefreshTokensPlusResponseDto({ message: 'Verification resent', tokens: mockTokens });
      mockAuthService.resendVerification.mockResolvedValue(expectedResult);

      const result = await controller.resendVerificationEmail(mockUserPayload);

      expect(authService.resendVerification).toHaveBeenCalledWith(mockUserPayload);
      expect(result).toEqual(expectedResult);
    });
  });

  describe('enable2FA', () => {
    it('should call authService.enable2FA and return its result', async () => {
      // Note: Controller type hint is Promise<MessageResponseDto>, but service returns Promise<RefreshTokensPlusResponseDto>.
      // Testing based on actual service return type.
      const expectedResult = new RefreshTokensPlusResponseDto({ message: '2FA enabled', tokens: mockTokens });
      mockAuthService.enable2FA.mockResolvedValue(expectedResult);

      const result = await controller.enable2FA(mockUserPayload);

      expect(authService.enable2FA).toHaveBeenCalledWith(mockUserPayload);
      expect(result).toEqual(expectedResult);
    });
  });

  describe('disable2FA', () => {
    it('should call authService.disable2FA and return its result', async () => {
      const expectedResult = new RefreshTokensPlusResponseDto({ message: '2FA disabled', tokens: mockTokens });
      mockAuthService.disable2FA.mockResolvedValue(expectedResult);

      const result = await controller.disable2FA(mockUserPayload);

      expect(authService.disable2FA).toHaveBeenCalledWith(mockUserPayload);
      expect(result).toEqual(expectedResult);
    });
  });

  describe('verify2FA', () => {
    it('should call authService.verify2FA and return its result', async () => {
      const verifyDto: Verify2FARequestDto = { code: '123456', userName: 'XXXXXXXX' };
      const expectedResult = new RefreshTokensResponseDto(mockTokens);
      mockAuthService.verify2FA.mockResolvedValue(expectedResult);

      const result = await controller.verify2FA(mockUserPayload, verifyDto);

      expect(authService.verify2FA).toHaveBeenCalledWith(verifyDto, mockUserPayload);
      expect(result).toEqual(expectedResult);
    });
  });
});
