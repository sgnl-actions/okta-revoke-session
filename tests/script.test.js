import { jest } from '@jest/globals';
import script from '../src/script.mjs';

// Mock fetch globally
global.fetch = jest.fn();

describe('Okta Revoke Session Action', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('invoke handler', () => {
    test('should successfully revoke sessions with valid inputs', async () => {
      const params = {
        userId: 'user123',
        oktaDomain: 'example.okta.com'
      };

      const context = {
        secrets: {
          OKTA_API_TOKEN: 'SSWS test-token-123'
        }
      };

      // Mock successful API response (204 No Content)
      fetch.mockResolvedValueOnce({
        ok: true,
        status: 204
      });

      const result = await script.invoke(params, context);

      expect(result).toEqual({
        userId: 'user123',
        sessionsRevoked: true,
        oktaDomain: 'example.okta.com',
        revokedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/)
      });

      expect(fetch).toHaveBeenCalledWith(
        'https://example.okta.com/api/v1/users/user123/sessions',
        {
          method: 'DELETE',
          headers: {
            'Authorization': 'SSWS test-token-123',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
          }
        }
      );
    });

    test('should add SSWS prefix to token if missing', async () => {
      const params = {
        userId: 'user456',
        oktaDomain: 'test.okta.com'
      };

      const context = {
        secrets: {
          OKTA_API_TOKEN: 'token-without-prefix'
        }
      };

      fetch.mockResolvedValueOnce({
        ok: true,
        status: 204
      });

      await script.invoke(params, context);

      expect(fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'SSWS token-without-prefix'
          })
        })
      );
    });

    test('should throw error when API token is missing', async () => {
      const params = {
        userId: 'user789',
        oktaDomain: 'example.okta.com'
      };

      const context = {
        secrets: {}
      };

      await expect(script.invoke(params, context)).rejects.toThrow(
        'Missing required secret: OKTA_API_TOKEN'
      );

      expect(fetch).not.toHaveBeenCalled();
    });

    test('should handle API error responses', async () => {
      const params = {
        userId: 'invalid-user',
        oktaDomain: 'example.okta.com'
      };

      const context = {
        secrets: {
          OKTA_API_TOKEN: 'SSWS test-token'
        }
      };

      // Mock 404 Not Found response
      fetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: async () => ({
          errorCode: 'E0000007',
          errorSummary: 'Not found: Resource not found: invalid-user (User)'
        })
      });

      const error = await script.invoke(params, context).catch(e => e);

      expect(error).toBeInstanceOf(Error);
      expect(error.message).toContain('Not found: Resource not found');
      expect(error.statusCode).toBe(404);
    });

    test('should handle non-JSON error responses', async () => {
      const params = {
        userId: 'user123',
        oktaDomain: 'example.okta.com'
      };

      const context = {
        secrets: {
          OKTA_API_TOKEN: 'SSWS test-token'
        }
      };

      // Mock 500 error with non-JSON response
      fetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: async () => {
          throw new Error('Invalid JSON');
        }
      });

      const error = await script.invoke(params, context).catch(e => e);

      expect(error).toBeInstanceOf(Error);
      expect(error.message).toBe('Failed to revoke sessions: HTTP 500');
      expect(error.statusCode).toBe(500);
    });
  });

  describe('error handler', () => {
    test('should retry on rate limit (429) and succeed', async () => {
      const params = {
        userId: 'user123',
        oktaDomain: 'example.okta.com',
        error: {
          message: 'Failed to revoke sessions: HTTP 429',
          statusCode: 429
        }
      };

      const context = {
        secrets: {
          OKTA_API_TOKEN: 'SSWS test-token'
        }
      };

      // Mock successful retry
      fetch.mockResolvedValueOnce({
        ok: true,
        status: 204
      });

      // Mock setTimeout to speed up test
      jest.useFakeTimers();
      const resultPromise = script.error(params, context);
      jest.runAllTimers();
      const result = await resultPromise;
      jest.useRealTimers();

      expect(result).toEqual({
        userId: 'user123',
        sessionsRevoked: true,
        oktaDomain: 'example.okta.com',
        revokedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
        recoveryMethod: 'rate_limit_retry'
      });

      expect(fetch).toHaveBeenCalledTimes(1);
    });

    test('should retry on service unavailable (503) and succeed', async () => {
      const params = {
        userId: 'user456',
        oktaDomain: 'test.okta.com',
        error: {
          message: 'Service temporarily unavailable',
          statusCode: 503
        }
      };

      const context = {
        secrets: {
          OKTA_API_TOKEN: 'test-token'
        }
      };

      // Mock successful retry
      fetch.mockResolvedValueOnce({
        ok: true,
        status: 204
      });

      // Mock setTimeout to speed up test
      jest.useFakeTimers();
      const resultPromise = script.error(params, context);
      jest.runAllTimers();
      const result = await resultPromise;
      jest.useRealTimers();

      expect(result).toEqual({
        userId: 'user456',
        sessionsRevoked: true,
        oktaDomain: 'test.okta.com',
        revokedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
        recoveryMethod: 'service_retry'
      });
    });

    test('should throw error when cannot recover', async () => {
      const params = {
        userId: 'user789',
        oktaDomain: 'example.okta.com',
        error: {
          message: 'Unauthorized: Invalid API token',
          statusCode: 401
        }
      };

      const context = {
        secrets: {
          OKTA_API_TOKEN: 'invalid-token'
        }
      };

      await expect(script.error(params, context)).rejects.toThrow(
        'Unrecoverable error revoking sessions for user user789: Unauthorized: Invalid API token'
      );

      expect(fetch).not.toHaveBeenCalled();
    });

    test('should handle retry failure after rate limit', async () => {
      const params = {
        userId: 'user123',
        oktaDomain: 'example.okta.com',
        error: {
          message: 'Rate limited',
          statusCode: 429
        }
      };

      const context = {
        secrets: {
          OKTA_API_TOKEN: 'SSWS test-token'
        }
      };

      // Mock failed retry
      fetch.mockResolvedValueOnce({
        ok: false,
        status: 429
      });

      // Mock setTimeout to speed up test
      jest.useFakeTimers();
      const errorPromise = script.error(params, context);
      jest.runAllTimers();

      await expect(errorPromise).rejects.toThrow(
        'Unrecoverable error revoking sessions'
      );

      jest.useRealTimers();
    });
  });

  describe('halt handler', () => {
    test('should handle graceful shutdown', async () => {
      const params = {
        userId: 'user123',
        reason: 'timeout'
      };

      const context = {};

      const result = await script.halt(params, context);

      expect(result).toEqual({
        userId: 'user123',
        reason: 'timeout',
        haltedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
        cleanupCompleted: true
      });
    });

    test('should handle halt with missing userId', async () => {
      const params = {
        reason: 'cancelled'
      };

      const context = {};

      const result = await script.halt(params, context);

      expect(result).toEqual({
        userId: 'unknown',
        reason: 'cancelled',
        haltedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
        cleanupCompleted: true
      });
    });
  });
});