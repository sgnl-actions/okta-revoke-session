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
        address: 'https://example.okta.com'
      };

      const context = {
        secrets: {
          BEARER_AUTH_TOKEN: 'SSWS test-token-123'
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
        address: 'https://example.okta.com',
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
        address: 'https://test.okta.com'
      };

      const context = {
        secrets: {
          BEARER_AUTH_TOKEN: 'token-without-prefix'
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
        address: 'https://example.okta.com'
      };

      const context = {
        secrets: {}
      };

      await expect(script.invoke(params, context)).rejects.toThrow(
        'No authentication configured'
      );

      expect(fetch).not.toHaveBeenCalled();
    });

    test('should handle API error responses', async () => {
      const params = {
        userId: 'invalid-user',
        address: 'https://example.okta.com'
      };

      const context = {
        secrets: {
          BEARER_AUTH_TOKEN: 'SSWS test-token'
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
        address: 'https://example.okta.com'
      };

      const context = {
        secrets: {
          BEARER_AUTH_TOKEN: 'SSWS test-token'
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
    test('should re-throw error for framework to handle', async () => {
      const testError = new Error('Failed to revoke sessions: HTTP 429');
      testError.statusCode = 429;

      const params = {
        userId: 'user123',
        address: 'https://example.okta.com',
        error: testError
      };

      const context = {
        secrets: {
          BEARER_AUTH_TOKEN: 'SSWS test-token'
        }
      };

      await expect(script.error(params, context)).rejects.toThrow(testError);
      expect(fetch).not.toHaveBeenCalled();
    });

    test('should log error details', async () => {
      const consoleSpy = jest.spyOn(console, 'error');
      const testError = new Error('Service unavailable');
      testError.statusCode = 503;

      const params = {
        userId: 'user456',
        address: 'https://test.okta.com',
        error: testError
      };

      const context = {};

      try {
        await script.error(params, context);
      } catch {
        // Expected to throw
      }

      expect(consoleSpy).toHaveBeenCalledWith(
        'Session revocation failed for user user456: Service unavailable'
      );
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