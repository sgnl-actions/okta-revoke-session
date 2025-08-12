/**
 * Okta Revoke Session Action
 *
 * Revokes all active sessions for an Okta user, forcing them to re-authenticate.
 * This is commonly used for security incidents or when user credentials may be compromised.
 */

/**
 * Helper function to perform session revocation
 * @private
 */
async function revokeUserSessions(userId, oktaDomain, authToken) {
  // Safely encode userId to prevent injection
  const encodedUserId = encodeURIComponent(userId);
  const url = new URL(`/api/v1/users/${encodedUserId}/sessions`, `https://${oktaDomain}`);

  const authHeader = authToken.startsWith('SSWS ') ? authToken : `SSWS ${authToken}`;

  const response = await fetch(url.toString(), {
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
   * @param {string} params.oktaDomain - The Okta domain (e.g., example.okta.com)
   * @param {Object} context - Execution context with env, secrets, outputs
   * @returns {Object} Job results
   */
  invoke: async (params, context) => {
    const { userId, oktaDomain } = params;

    console.log(`Starting Okta session revocation for user: ${userId}`);

    // Validate inputs
    if (!userId || typeof userId !== 'string') {
      throw new Error('Invalid or missing userId parameter');
    }
    if (!oktaDomain || typeof oktaDomain !== 'string') {
      throw new Error('Invalid or missing oktaDomain parameter');
    }

    // Validate Okta API token is present
    if (!context.secrets?.OKTA_API_TOKEN) {
      throw new Error('Missing required secret: OKTA_API_TOKEN');
    }

    // Make the API request to revoke sessions
    const response = await revokeUserSessions(
      userId,
      oktaDomain,
      context.secrets.OKTA_API_TOKEN
    );

    // Handle the response
    if (response.ok) {
      // 204 No Content is the expected success response
      console.log(`Successfully revoked all sessions for user ${userId}`);

      return {
        userId: userId,
        sessionsRevoked: true,
        oktaDomain: oktaDomain,
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
    const { error, userId, oktaDomain } = params;
    const statusCode = error.statusCode;

    console.error(`Session revocation failed for user ${userId}: ${error.message}`);

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
        oktaDomain,
        context.secrets.OKTA_API_TOKEN
      );

      if (retryResponse.ok) {
        console.log(`Successfully revoked sessions for user ${userId} after retry`);

        return {
          userId: userId,
          sessionsRevoked: true,
          oktaDomain: oktaDomain,
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
        oktaDomain,
        context.secrets.OKTA_API_TOKEN
      );

      if (retryResponse.ok) {
        console.log(`Successfully revoked sessions for user ${userId} after service recovery`);

        return {
          userId: userId,
          sessionsRevoked: true,
          oktaDomain: oktaDomain,
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

    // No cleanup needed for this simple operation
    // The DELETE request either completed or didn't

    return {
      userId: userId || 'unknown',
      reason: reason,
      haltedAt: new Date().toISOString(),
      cleanupCompleted: true
    };
  }
};