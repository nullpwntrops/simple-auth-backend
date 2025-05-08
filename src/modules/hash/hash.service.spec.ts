import { Test, TestingModule } from '@nestjs/testing';
import * as bcrypt from 'bcrypt';
import { HashService } from './hash.service';

// Let's walk through what these tests do:

// 1.  **Mock `bcrypt`**:
//     *   `jest.mock('bcrypt', ...)` at the top replaces the actual `bcrypt` library
//     *    with mock functions. This gives us full control over what `bcrypt.genSalt`,
//     *    `bcrypt.hash`, and `bcrypt.compare` return.
// 2.  **`beforeEach`**:
//     *   A new `TestingModule` is created with `HashService` for each test.
//     *   `jest.clearAllMocks()` is crucial to reset the state of our mocks (like call
//     *   counts and mock implementations) before each test runs, preventing interference between tests.
// 3.  **`hash` method tests**:
//     *   **Valid input**: We check if `bcrypt.genSalt` is called with the correct `SALT_OR_ROUNDS`
//           (accessed via `service['SALT_OR_ROUNDS']` because it's private) and if `bcrypt.hash` is
//           called with the input and the generated salt. We also verify the returned hashed value.
//     *   **Invalid inputs (null, undefined, empty string)**: We ensure that for these falsy inputs,
//           the service returns `null` and `bcrypt` functions are not called, matching your service's logic.
// 4.  **`compare` method tests**:
//     *   **Matching input/hash**: We mock `bcrypt.compare` to return `true` and verify that the
//           service method also returns `true`.
//     *   **Non-matching input/hash**: We mock `bcrypt.compare` to return `false` and verify the
//           service method returns `false`.
//     *   **Invalid inputs**: Using `it.each`, we test various combinations of null, undefined, or
//           empty strings for either the input or the hash. In all these cases, the service should
//           return `false` without calling `bcrypt.compare`, as per your service's guard clauses.

// Mock the bcrypt library
jest.mock('bcrypt', () => ({
  genSalt: jest.fn(),
  hash: jest.fn(),
  compare: jest.fn(),
}));

describe('HashService', () => {
  let service: HashService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [HashService],
    }).compile();

    service = module.get<HashService>(HashService);
    // Clear all mock implementations and calls before each test
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('hash', () => {
    const mockSalt = 'mockSaltValue';
    const mockHashedValue = 'mockHashedPassword';

    it('should correctly hash a given input string', async () => {
      const input = 'mySecretPassword';
      (bcrypt.genSalt as jest.Mock).mockResolvedValue(mockSalt);
      (bcrypt.hash as jest.Mock).mockResolvedValue(mockHashedValue);

      const result = await service.hash(input);

      expect(bcrypt.genSalt).toHaveBeenCalledWith(service['SALT_OR_ROUNDS']);
      expect(bcrypt.hash).toHaveBeenCalledWith(input, mockSalt);
      expect(result).toBe(mockHashedValue);
    });

    it('should return null if the input string is null', async () => {
      const result = await service.hash(null);
      expect(result).toBeNull();
      expect(bcrypt.genSalt).not.toHaveBeenCalled();
      expect(bcrypt.hash).not.toHaveBeenCalled();
    });

    it('should return null if the input string is undefined', async () => {
      const result = await service.hash(undefined);
      expect(result).toBeNull();
      expect(bcrypt.genSalt).not.toHaveBeenCalled();
      expect(bcrypt.hash).not.toHaveBeenCalled();
    });

    it('should return null if the input string is empty', async () => {
      // The current implementation treats empty string as falsy and returns null.
      // If an empty string should be hashed, the service logic would need adjustment.
      const result = await service.hash('');
      expect(result).toBeNull();
      expect(bcrypt.genSalt).not.toHaveBeenCalled();
      expect(bcrypt.hash).not.toHaveBeenCalled();
    });
  });

  describe('compare', () => {
    it('should return true if the input matches the hash', async () => {
      const input = 'mySecretPassword';
      const hash = 'mockHashedPassword';
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);

      const result = await service.compare(input, hash);

      expect(bcrypt.compare).toHaveBeenCalledWith(input, hash);
      expect(result).toBe(true);
    });

    it('should return false if the input does not match the hash', async () => {
      const input = 'wrongPassword';
      const hash = 'mockHashedPassword';
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      const result = await service.compare(input, hash);

      expect(bcrypt.compare).toHaveBeenCalledWith(input, hash);
      expect(result).toBe(false);
    });

    it.each([
      [null, 'hash'],
      ['input', null],
      [undefined, 'hash'],
      ['input', undefined],
      ['', 'hash'],
      ['input', ''],
    ])('should return false if input (%s) or hash (%s) is invalid', async (input, hash) => {
      const result = await service.compare(input as string, hash as string);
      expect(result).toBe(false);
      expect(bcrypt.compare).not.toHaveBeenCalled();
    });
  });
});
