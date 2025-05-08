import { BadRequestException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { v4 as uuid4 } from 'uuid';
import { PinoLogger } from 'nestjs-pino';
import { AppConfig, getConfig } from '../../common/config/service-config';
import { addInterval } from '../../common/utilities/date-time';
import { Enums } from '../../common/constants';
import { UserEntity } from '../../database/entities/user.entity';
import { HashService } from '../hash/hash.service';
import { UserService } from './user.service';

// Mock external dependencies
jest.mock('uuid', () => ({
  v4: jest.fn(),
}));
jest.mock('../../common/config/service-config', () => ({
  getConfig: jest.fn(),
}));
jest.mock('../../common/utilities/date-time', () => ({
  addInterval: jest.fn(),
}));

const mockUserEntity = new UserEntity();
mockUserEntity.id = 'user-id-123';
mockUserEntity.email = 'test@example.com';
mockUserEntity.userName = 'testuser';
mockUserEntity.password = 'hashedPassword';
mockUserEntity.role = Enums.UserRoles.USER;

describe('UserService', () => {
  let service: UserService;
  let userRepository: Repository<UserEntity>;
  let hashService: HashService;
  let logger: PinoLogger;

  const mockAppConfig: Partial<AppConfig> = {
    jwt: {
      verifyExpiration: '1d', // Example value
    } as any,
  };

  const mockHashedPassword = 'hashedTestPassword';
  const mockHashedToken = 'hashedTestToken';
  const mockVerificationToken = 'mock-uuid-verification-token';
  const mockVerificationTokenExpiresAt = new Date('2023-01-02T00:00:00.000Z');

  beforeEach(async () => {
    // Clear mocks that might have been called during instantiation or by other tests
    jest.clearAllMocks();

    (getConfig as jest.Mock).mockReturnValue(mockAppConfig);
    (uuid4 as jest.Mock).mockReturnValue(mockVerificationToken);
    (addInterval as jest.Mock).mockReturnValue(mockVerificationTokenExpiresAt);

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserService,
        {
          provide: getRepositoryToken(UserEntity),
          useValue: {
            save: jest.fn(),
            findOneBy: jest.fn(),
          },
        },
        {
          provide: HashService,
          useValue: {
            hash: jest.fn().mockResolvedValue(mockHashedPassword), // Default mock
          },
        },
        {
          provide: PinoLogger,
          useValue: {
            setContext: jest.fn(),
            info: jest.fn(),
            error: jest.fn(),
            warn: jest.fn(),
            debug: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<UserService>(UserService);
    userRepository = module.get<Repository<UserEntity>>(getRepositoryToken(UserEntity));
    hashService = module.get<HashService>(HashService);
    logger = module.get<PinoLogger>(PinoLogger);

    // Re-apply mocks that are set up in beforeEach for clarity and to override module-level mocks if needed
    (getConfig as jest.Mock).mockReturnValue(mockAppConfig);
    (uuid4 as jest.Mock).mockReturnValue(mockVerificationToken);
    (addInterval as jest.Mock).mockReturnValue(mockVerificationTokenExpiresAt);
    (hashService.hash as jest.Mock).mockResolvedValue(mockHashedPassword); // Reset default hash mock
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('constructor', () => {
    it('should set logger context and load config', () => {
      // Constructor is called during module setup, so these are checked implicitly by module init
      // To explicitly test, we'd need to re-instantiate or check calls from the initial setup
      expect(logger.setContext).toHaveBeenCalledWith(UserService.name);
      expect(getConfig).toHaveBeenCalledTimes(1); // Called during initial instantiation
    });
  });

  describe('createUser', () => {
    let newUserInput: UserEntity;

    beforeEach(() => {
      newUserInput = { ...new UserEntity(), email: 'new@example.com', password: 'plainPassword' };
    });

    it('should create a new user successfully', async () => {
      (hashService.hash as jest.Mock)
        .mockResolvedValueOnce(mockHashedToken) // For verificationToken
        .mockResolvedValueOnce(mockHashedPassword); // For password
      // jest.spyOn(userRepository, 'save').mockResolvedValue({ ...newUserInput, id: 'new-id' } as UserEntity);
      // Use mockImplementation to ensure the returned object reflects modifications made by the service
      jest.spyOn(userRepository, 'save').mockImplementation(async (userToSave: UserEntity) => {
        return { ...userToSave, id: 'new-id' } as UserEntity;
      });
      const result = await service.createUser(newUserInput);

      expect(result.role).toBe(Enums.UserRoles.USER);
      expect(uuid4).toHaveBeenCalledTimes(1);
      expect(hashService.hash).toHaveBeenNthCalledWith(1, mockVerificationToken);
      expect(result.verificationToken).toBe(mockHashedToken);
      expect(addInterval).toHaveBeenCalledWith(mockAppConfig.jwt.verifyExpiration);
      expect(result.verificationTokenExpiresAt).toBe(mockVerificationTokenExpiresAt);
      expect(hashService.hash).toHaveBeenNthCalledWith(2, 'plainPassword');
      expect(result.password).toBe(mockHashedPassword);
      expect(userRepository.save).toHaveBeenCalledWith(expect.objectContaining(newUserInput));
      expect(result.id).toBe('new-id');
    });

    it('should throw BadRequestException if userRepository.save fails', async () => {
      jest.spyOn(userRepository, 'save').mockRejectedValue(new Error('DB save error'));
      await expect(service.createUser(newUserInput)).rejects.toThrow(
        new BadRequestException('Failed to create user: DB save error'),
      );
    });

    it('should re-throw BadRequestException if thrown internally', async () => {
      (hashService.hash as jest.Mock).mockRejectedValue(new BadRequestException('Hashing failed'));
      await expect(service.createUser(newUserInput)).rejects.toThrow(new BadRequestException('Hashing failed'));
    });
  });

  describe('findOne', () => {
    it.each([
      [{ id: 'test-id' }, { id: 'test-id' }],
      [{ email: 'test@example.com' }, { email: 'test@example.com' }],
      [{ userName: 'testuser' }, { userName: 'testuser' }],
      [{ verificationToken: 'vToken' }, { verificationToken: 'vToken' }],
      [{ resetToken: 'rToken' }, { resetToken: 'rToken' }],
    ])('should find a user by %s', async (searchCriteria, expectedQuery) => {
      jest.spyOn(userRepository, 'findOneBy').mockResolvedValue(mockUserEntity);
      const result = await service.findOne(searchCriteria as Partial<UserEntity>);
      expect(userRepository.findOneBy).toHaveBeenCalledWith(expectedQuery);
      expect(result).toEqual(mockUserEntity);
    });

    it('should return null if user is not found', async () => {
      jest.spyOn(userRepository, 'findOneBy').mockResolvedValue(null);
      const result = await service.findOne({ email: 'notfound@example.com' });
      expect(result).toBeNull();
    });

    it('should throw BadRequestException if userRepository.findOneBy fails', async () => {
      jest.spyOn(userRepository, 'findOneBy').mockRejectedValue(new Error('DB find error'));
      await expect(service.findOne({ email: 'any@example.com' })).rejects.toThrow(
        new BadRequestException('Failed to find user: DB find error'),
      );
    });

    it('should throw BadRequestException (converted from UnauthorizedException) if no valid search criteria provided', async () => {
      // buildUserSearchQuery throws UnauthorizedException, which findOne catches and re-throws as BadRequestException
      await expect(service.findOne({})).rejects.toThrow(new BadRequestException('Failed to find user: User not found'));
    });
  });

  describe('updateUser', () => {
    let userDto: UserEntity;
    const existingUser = {
      ...mockUserEntity,
      id: 'existing-id',
      email: 'existing@example.com',
      password: 'oldHashedPassword',
    };

    beforeEach(() => {
      userDto = { ...new UserEntity(), email: existingUser.email, userName: 'updatedUser' };
      jest.spyOn(service, 'findOne').mockResolvedValue(existingUser as UserEntity); // Mock internal findOne call
      jest.spyOn(userRepository, 'save').mockImplementation(async (user) => user as UserEntity);
    });

    it('should throw NotFoundException if user to update is not found', async () => {
      jest.spyOn(service, 'findOne').mockResolvedValue(null);
      await expect(service.updateUser(userDto)).rejects.toThrow(new NotFoundException('User not found'));
    });

    it('should update user without hashing password or tokens', async () => {
      const result = await service.updateUser(userDto, false, false);
      expect(hashService.hash).not.toHaveBeenCalled();
      expect(userRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({ ...existingUser, userName: 'updatedUser' }),
      );
      expect(result.userName).toBe('updatedUser');
      expect(result.password).toBeUndefined(); // Password should be stripped
    });

    it('should update user and hash password if hashPwd is true and password provided', async () => {
      userDto.password = 'newPlainPassword';
      (hashService.hash as jest.Mock).mockResolvedValue('newHashedPassword');

      const result = await service.updateUser(userDto, true, false);

      expect(hashService.hash).toHaveBeenCalledWith('newPlainPassword');
      expect(userRepository.save).toHaveBeenCalledWith(expect.objectContaining({ password: 'newHashedPassword' }));
      expect(result.password).toBeUndefined();
    });

    it('should update user and hash tokens if hashTokens is true', async () => {
      userDto.accessToken = 'newAccessToken';
      userDto.refreshToken = 'newRefreshToken';
      (hashService.hash as jest.Mock)
        .mockResolvedValueOnce('hashedNewAccessToken')
        .mockResolvedValueOnce('hashedNewRefreshToken');

      const result = await service.updateUser(userDto, false, true);

      expect(hashService.hash).toHaveBeenCalledWith('newAccessToken');
      expect(hashService.hash).toHaveBeenCalledWith('newRefreshToken');
      expect(userRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          accessToken: 'hashedNewAccessToken',
          refreshToken: 'hashedNewRefreshToken',
        }),
      );
      expect(result.password).toBeUndefined();
    });

    it('should return user without password field', async () => {
      const userWithPassword = { ...existingUser, ...userDto, password: 'somePasswordInDb' };
      jest.spyOn(userRepository, 'save').mockResolvedValue(userWithPassword as UserEntity);
      const result = await service.updateUser(userDto);
      expect(result.password).toBeUndefined();
      expect(result.email).toBe(userDto.email);
    });

    it('should throw BadRequestException if userRepository.save fails', async () => {
      jest.spyOn(userRepository, 'save').mockRejectedValue(new Error('DB save error'));
      await expect(service.updateUser(userDto)).rejects.toThrow(
        new BadRequestException('Failed to update user by email: DB save error'),
      );
    });

    it.each([
      new UnauthorizedException('Auth error'),
      new NotFoundException('Another not found'),
      new BadRequestException('Bad req internal'),
    ])('should re-throw specific exceptions if they occur', async (thrownError) => {
      jest.spyOn(service, 'findOne').mockRejectedValue(thrownError); // Simulate error from findOne
      await expect(service.updateUser(userDto)).rejects.toThrow(thrownError);
    });
  });

  describe('checkUserAlreadyExists', () => {
    it('should throw BadRequestException if no email or username is provided', async () => {
      const userObj = new UserEntity(); // No email or username
      await expect(service.checkUserAlreadyExists(userObj)).rejects.toThrow(
        new BadRequestException('Email or username is required!'),
      );
    });

    it('should return true if user exists by email', async () => {
      const userObj = { ...new UserEntity(), email: 'exists@example.com' };
      jest.spyOn(userRepository, 'findOneBy').mockResolvedValue(userObj as UserEntity);
      const result = await service.checkUserAlreadyExists(userObj);
      expect(userRepository.findOneBy).toHaveBeenCalledWith({ email: 'exists@example.com' });
      expect(result).toBe(true);
    });

    it('should return true if user exists by username', async () => {
      // To be precise, let's test with only username
      const userObj = { ...new UserEntity(), userName: 'existsUser' };
      // Use mockImplementationOnce for clarity on the first call's behavior
      (userRepository.findOneBy as jest.Mock).mockImplementationOnce(async (query) => {
        if (query.userName === 'existsUser') return userObj as UserEntity;
        return null;
      });
      const result = await service.checkUserAlreadyExists(userObj);
      expect(userRepository.findOneBy).toHaveBeenCalledWith({ userName: 'existsUser' });
      expect(userRepository.findOneBy).toHaveBeenCalledTimes(1);
      expect(result).toBe(true);
    });

    it('should return true if user exists by email even if username is also provided', async () => {
      const userObj = { ...new UserEntity(), email: 'exists@example.com', userName: 'someUser' };
      // Use mockImplementationOnce for clarity on the first call's behavior
      (userRepository.findOneBy as jest.Mock).mockImplementationOnce(async (query) => {
        if (query.email === 'exists@example.com') return userObj as UserEntity;
        return null;
      });
      const result = await service.checkUserAlreadyExists(userObj);
      expect(userRepository.findOneBy).toHaveBeenCalledWith({ email: 'exists@example.com' });
      // findOneBy for username should not be called if email match was found
      expect(userRepository.findOneBy).toHaveBeenCalledTimes(1);
      expect(result).toBe(true);
    });

    it('should return false if user does not exist by email or username', async () => {
      const userObj = { ...new UserEntity(), email: 'new@example.com', userName: 'newUser' };
      jest.spyOn(userRepository, 'findOneBy').mockResolvedValue(null); // Both email and username checks return null
      const result = await service.checkUserAlreadyExists(userObj);
      expect(userRepository.findOneBy).toHaveBeenCalledWith({ email: 'new@example.com' });
      expect(userRepository.findOneBy).toHaveBeenCalledWith({ userName: 'newUser' });
      expect(result).toBe(false);
    });
  });

  describe('buildUserSearchQuery (private method - tested via findOne or directly if needed)', () => {
    // This method is private, typically tested via the public methods that use it (like findOne).
    // However, if its logic is complex, you might expose it or test it like this:
    const callBuildUserSearchQuery = (data: Partial<UserEntity>) => {
      return (service as any).buildUserSearchQuery(data);
    };

    it('should return query for id if id is present', () => {
      const query = callBuildUserSearchQuery({ id: '123', email: 'test@test.com' });
      expect(query).toEqual({ id: '123' });
    });

    it('should return query for email if email is present and id is not', () => {
      const query = callBuildUserSearchQuery({ email: 'test@test.com', userName: 'tester' });
      expect(query).toEqual({ email: 'test@test.com' });
    });

    it('should return query for userName if userName is present and id/email are not', () => {
      const query = callBuildUserSearchQuery({ userName: 'tester', verificationToken: 'vtok' });
      expect(query).toEqual({ userName: 'tester' });
    });

    it('should return query for verificationToken if present and id/email/userName are not', () => {
      const query = callBuildUserSearchQuery({ verificationToken: 'vtok', resetToken: 'rtok' });
      expect(query).toEqual({ verificationToken: 'vtok' });
    });

    it('should return query for resetToken if present and others are not', () => {
      const query = callBuildUserSearchQuery({ resetToken: 'rtok' });
      expect(query).toEqual({ resetToken: 'rtok' });
    });

    it('should throw UnauthorizedException if no valid fields are provided', () => {
      expect(() => callBuildUserSearchQuery({})).toThrow(new UnauthorizedException('User not found'));
      expect(() => callBuildUserSearchQuery({ isLockedReason: 'string' })).toThrow(
        new UnauthorizedException('User not found'),
      );
    });
  });
});
