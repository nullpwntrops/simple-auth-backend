import { Injectable, UnauthorizedException, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { PinoLogger } from 'nestjs-pino';
import { v4 as uuid4 } from 'uuid';
import { Enums } from '../../common/constants';
import { AppConfig, getConfig } from '../../common/config/service-config';
import { addInterval } from '../../common/utilities/date-time';
import { UserEntity } from '../../database/entities/user.entity';
import { HashService } from '../hash/hash.service';

@Injectable()
export class UserService {
  //*****************************
  //#region Local variables
  //*****************************

  private readonly config: AppConfig;

  //#endregion
  //*****************************

  //*****************************
  //#region Constructors
  //*****************************

  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,
    private readonly hashService: HashService,
    private readonly logger: PinoLogger,
  ) {
    this.logger.setContext(UserService.name);
    this.config = getConfig();
  }

  //#endregion
  //*****************************

  //*****************************
  //#region Public Methods
  //*****************************

  /**
   * Function to create a new user.
   *
   * @param {UserEntity} newUser User details to add to database
   * @return {*}  {Promise<UserEntity>}
   * @memberof UserService
   */
  public async createUser(newUser: UserEntity): Promise<UserEntity> {
    try {
      // Assign user to the default role
      newUser.role = Enums.UserRoles.USER;

      // Generate a verification token and hash it
      const verificationToken = uuid4();
      newUser.verificationToken = await this.hashService.hash(verificationToken);
      newUser.verificationTokenExpiresAt = addInterval(this.config.jwt.verifyExpiration);

      // Hash password
      newUser.password = await this.hashService.hash(newUser.password);

      // Create new user record in the database and return it
      return await this.userRepository.save(newUser);
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      throw new BadRequestException('Failed to create user: ' + error.message);
    }
  }

  /**
   * Function to find a user by id, email, username, verification token,
   * or reset token
   *
   * @param {Partial<UserEntity>} data - Object that contains user's info to search
   * @return {*}  {Promise<UserEntity>} - User object if found.  Null otherwise.
   * @memberof UserService
   */
  public async findOne(data: Partial<UserEntity>): Promise<UserEntity> {
    try {
      const query = this.buildUserSearchQuery(data);
      const user = await this.userRepository.findOneBy(query);
      return user;
    } catch (error) {
      // TODO: Should we throw an error?  Or just return null?
      throw new BadRequestException('Failed to find user: ' + error.message);
    }
  }

  /**
   * Function to update a user
   *
   * @param {UserEntity} userDto - Object that contains user's info to update
   * @param {boolean} [hashPwd=false] - Flag to indicate if password should be updated
   * @param {boolean} [hashTokens=false] - Flag to indicate if tokens should be updated
   * @return {*}  {Promise<UserEntity>} - Updated user object
   * @memberof UserService
   */
  public async updateUser(
    userDto: UserEntity,
    hashPwd: boolean = false,
    hashTokens: boolean = false,
  ): Promise<UserEntity> {
    try {
      // Fetch user from database
      const user = await this.findOne({ email: userDto.email });
      if (!user) {
        throw new NotFoundException(`User not found`);
      }

      // Hash password if necessary
      if (hashPwd && userDto.password) {
        userDto.password = await this.hashService.hash(userDto.password);
      }

      // Hash tokens if necessary
      if (hashTokens) {
        userDto.accessToken = await this.hashService.hash(userDto.accessToken);
        userDto.refreshToken = await this.hashService.hash(userDto.refreshToken);
      }

      // Update user object
      const updatedUser = Object.assign(user, userDto);

      // Save to the database
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password, ...retUser } = await this.userRepository.save(updatedUser);

      // Return updated object to caller minus the password
      return <UserEntity>retUser;
    } catch (error) {
      if (
        error instanceof UnauthorizedException ||
        error instanceof NotFoundException ||
        error instanceof BadRequestException
      ) {
        throw error;
      }
      throw new BadRequestException(`Failed to update user by email: ${error.message}`);
    }
  }

  /**
   * Function to check if a user already exists in the database
   *
   * @param {UserEntity} userObj - Object that contains user's info to search
   * @return {*}  {Promise<boolean>} - True if user exists.  False otherwise.
   * @memberof UserService
   */
  public async checkUserAlreadyExists(userObj: UserEntity): Promise<boolean> {
    // Step 1: Check that email and/or username was passed through
    if (!userObj.email && !userObj.userName) {
      throw new BadRequestException('Email or username is required!');
    }

    // Step 2: Check if email or username already exists
    const fieldsToCheck = ['email', 'userName'];
    for (const field of fieldsToCheck) {
      if (userObj[field]) {
        const existingUser = await this.userRepository.findOneBy({ [field]: userObj[field] });
        if (existingUser) {
          return true;
        }
      }
    }
    return false;
  }

  //#endregion
  //*****************************

  //*****************************
  //#region Private Methods
  //*****************************

  /**
   * Function to build a query object for searching users
   *
   * @private
   * @param {Partial<UserEntity>} data - Object that contains user's info to search
   * @return {*}  {Partial<UserEntity>} - Query object to use for searching users
   * @memberof UserService
   */
  private buildUserSearchQuery(data: Partial<UserEntity>): Partial<UserEntity> {
    // Ordered list of fields to check.
    const fieldsToCheck = ['id', 'email', 'userName', 'verificationToken', 'resetToken'];
    for (const field of fieldsToCheck) {
      if (data[field]) {
        return { [field]: data[field] };
      }
    }
    // If all the fields are null, then throw an error.
    throw new UnauthorizedException('User not found');
  }

  //#endregion
  //*****************************
}
