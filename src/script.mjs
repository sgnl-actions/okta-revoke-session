/**
 * Okta Revoke Session Action
 *
 * Revokes all active sessions for an Okta user, forcing them to re-authenticate.
 * This is commonly used for security incidents or when user credentials may be compromised.
 */

import { getBaseUrl, getAuthorizationHeader } from '@sgnl-actions/utils';

/**
 * Helper function to perform session revocation
 * @private
 */
async function revokeUserSessions(userId, baseUrl, authHeader) {
  // Safely encode userId to prevent injection
  const encodedUserId = encodeURIComponent(userId);
  // Build URL using base URL (already cleaned by getBaseUrl)
  const url = `${baseUrl}/api/v1/users/${encodedUserId}/sessions`;

  const response = await fetch(url, {
    method: 'DELETE',
    headers: {
      'Authorization': authHeader,
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    }
  });

  return response;
}


export default {
  /**
   * Main execution handler - revokes all sessions for the specified Okta user
   * @param {Object} params - Job input parameters
   * @param {string} params.userId - The Okta user ID
   * @param {string} params.address - Full URL to Okta API (defaults to ADDRESS environment variable)
   *
   * @param {Object} context - Execution context with secrets and environment
   * @param {string} context.environment.ADDRESS - Default Okta API base URL
   *
   * The configured auth type will determine which of the following environment variables and secrets are available
   * @param {string} context.secrets.BEARER_AUTH_TOKEN
   *
   * @param {string} context.secrets.BASIC_USERNAME
   * @param {string} context.secrets.BASIC_PASSWORD
   *
   * @param {string} context.secrets.OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_AUDIENCE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_AUTH_STYLE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_SCOPE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL
   *
   * @param {string} context.secrets.OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN
   *
   * @returns {Object} Job results
   */
  invoke: async (params, context) => {
    const { userId } = params;

    console.log(`Starting Okta session revocation for user: ${userId}`);

    // Validate inputs
    if (!userId || typeof userId !== 'string') {
      throw new Error('Invalid or missing userId parameter');
    }

    // Get base URL using utility function
    const baseUrl = getBaseUrl(params, context);

    // Get authorization header
    let authHeader = await getAuthorizationHeader(context);

    // Handle Okta's SSWS token format for Bearer auth mode
    // Okta API tokens use "SSWS" prefix instead of "Bearer"
    if (authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7); // Remove "Bearer " prefix
      // If token already has SSWS prefix, use it as-is
      // Otherwise add SSWS prefix for Okta API tokens
      authHeader = token.startsWith('SSWS ') ? token : `SSWS ${token}`;
    }
    // For Basic and OAuth2 modes, use the header as returned by utils

    // Make the API request to revoke sessions
    const response = await revokeUserSessions(
      userId,
      baseUrl,
      authHeader
    );

    // Handle the response
    if (response.ok) {
      // 204 No Content is the expected success response
      console.log(`Successfully revoked all sessions for user ${userId}`);

      return {
        userId: userId,
        sessionsRevoked: true,
        address: baseUrl,
        revokedAt: new Date().toISOString()
      };
    }

    // Handle error responses
    const statusCode = response.status;
    let errorMessage = `Failed to revoke sessions: HTTP ${statusCode}`;

    try {
      const errorBody = await response.json();
      if (errorBody.errorSummary) {
        errorMessage = `Failed to revoke sessions: ${errorBody.errorSummary}`;
      }
      console.error('Okta API error response:', errorBody);
    } catch {
      // Response might not be JSON
      console.error('Failed to parse error response');
    }

    // Throw error with status code for proper error handling
    const error = new Error(errorMessage);
    error.statusCode = statusCode;
    throw error;
  },

  /**
   * Error recovery handler - attempts to recover from retryable errors
   * @param {Object} params - Original params plus error information
   * @param {Object} context - Execution context
   * @returns {Object} Recovery results
   */
  error: async (params, context) => {
    const { error, userId } = params;
    const statusCode = error.statusCode;

    console.error(`Session revocation failed for user ${userId}: ${error.message}`);

    // Get base URL using utility function
    const baseUrl = getBaseUrl(params, context);

    // Get authorization header
    let authHeader = await getAuthorizationHeader(context);

    // Handle Okta's SSWS token format for Bearer auth mode
    if (authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      authHeader = token.startsWith('SSWS ') ? token : `SSWS ${token}`;
    }

    // Get configurable backoff times from environment
    const rateLimitBackoffMs = parseInt(context.env?.RATE_LIMIT_BACKOFF_MS || '30000', 10);
    const serviceErrorBackoffMs = parseInt(context.env?.SERVICE_ERROR_BACKOFF_MS || '10000', 10);

    // Handle rate limiting (429)
    if (statusCode === 429 || error.message.includes('429') || error.message.includes('rate limit')) {
      console.log(`Rate limited by Okta API - waiting ${rateLimitBackoffMs}ms before retry`);
      await new Promise(resolve => setTimeout(resolve, rateLimitBackoffMs));

      console.log(`Retrying session revocation for user ${userId} after rate limit backoff`);

      // Retry the operation using helper function
      const retryResponse = await revokeUserSessions(
        userId,
        baseUrl,
        authHeader
      );

      if (retryResponse.ok) {
        console.log(`Successfully revoked sessions for user ${userId} after retry`);

        return {
          userId: userId,
          sessionsRevoked: true,
          address: baseUrl,
          revokedAt: new Date().toISOString(),
          recoveryMethod: 'rate_limit_retry'
        };
      }
    }

    // Handle temporary service issues (502, 503, 504)
    if ([502, 503, 504].includes(statusCode)) {
      console.log(`Okta service temporarily unavailable - waiting ${serviceErrorBackoffMs}ms before retry`);
      await new Promise(resolve => setTimeout(resolve, serviceErrorBackoffMs));

      console.log(`Retrying session revocation for user ${userId} after service interruption`);

      // Retry the operation using helper function
      const retryResponse = await revokeUserSessions(
        userId,
        baseUrl,
        authHeader
      );

      if (retryResponse.ok) {
        console.log(`Successfully revoked sessions for user ${userId} after service recovery`);

        return {
          userId: userId,
          sessionsRevoked: true,
          address: baseUrl,
          revokedAt: new Date().toISOString(),
          recoveryMethod: 'service_retry'
        };
      }
    }

    // Cannot recover from this error
    console.error(`Unable to recover from error for user ${userId}`);
    throw new Error(`Unrecoverable error revoking sessions for user ${userId}: ${error.message}`);
  },

  /**
   * Graceful shutdown handler - cleanup when job is halted
   * @param {Object} params - Original params plus halt reason
   * @param {Object} context - Execution context
   * @returns {Object} Cleanup results
   */
  halt: async (params, _context) => {
    const { reason, userId } = params;
    console.log(`Session revocation job is being halted (${reason}) for user ${userId}`);

    return {
      userId: userId || 'unknown',
      reason: reason,
      haltedAt: new Date().toISOString(),
      cleanupCompleted: true
    };
  }
};