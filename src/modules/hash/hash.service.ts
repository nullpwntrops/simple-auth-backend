import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

@Injectable()
export class HashService {
  //*****************************
  //#region Local Variables
  //*****************************

  private readonly SALT_OR_ROUNDS = 10;

  //#endregion
  //*****************************

  //*****************************
  //#region Public Methods
  //*****************************

  /**
   * Function to hash a string.
   *
   * @param {string} input - String to hash.
   * @return {*}  {Promise<string>} - The hashed string.
   * @memberof HashService
   */
  public async hash(input: string): Promise<string> {
    if (input) {
      const saltOrRounds = await bcrypt.genSalt(this.SALT_OR_ROUNDS);
      return bcrypt.hash(input, saltOrRounds);
    }
    return null;
  }

  /**
   * Function to compare a string with a hash.
   *
   * @param {string} input - String to compare.
   * @param {string} hash - Hash to compare with.
   * @return {*}  {Promise<boolean>} - True if the string matches the hash, false otherwise.
   * @memberof HashService
   */
  public async compare(input: string, hash: string): Promise<boolean> {
    if (!input || !hash) {
      return false;
    }
    return bcrypt.compare(input, hash);
  }

  //#endregion
  //*****************************
}
