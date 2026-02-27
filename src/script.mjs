/**
 * Okta Revoke Session Action
 *
 * Revokes all active sessions for an Okta user, forcing them to re-authenticate.
 * This is commonly used for security incidents or when user credentials may be compromised.
 */

import { getBaseURL, createHeaders } from '@sgnl-actions/utils';

/**
 * Helper function to perform session revocation
 * @private
 */
async function revokeUserSessions(userId, baseUrl, headers) {
  // Safely encode userId to prevent injection
  const encodedUserId = encodeURIComponent(userId);
  // Build URL using base URL (already cleaned by getBaseUrl)
  const url = `${baseUrl}/api/v1/users/${encodedUserId}/sessions`;

  const response = await fetch(url, {
    method: 'DELETE',
    headers
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

    // Get base URL using utility function
    const baseUrl = getBaseURL(params, context);

    // Get headers using utility function
    let headers = await createHeaders(context);

    // Handle Okta's SSWS token format - only for Bearer token auth mode
    // Okta API tokens use "SSWS" prefix instead of "Bearer"
    if (context.secrets.BEARER_AUTH_TOKEN && headers['Authorization'].startsWith('Bearer ')) {
      const token = headers['Authorization'].substring(7); // Remove "Bearer " prefix
      // If token already has SSWS prefix, use it as-is
      // Otherwise add SSWS prefix for Okta API tokens
      headers['Authorization'] = token.startsWith('SSWS ') ? token : `SSWS ${token}`;
    }
    // For Basic and OAuth2 modes, use the header as returned by utils

    // Make the API request to revoke sessions
    const response = await revokeUserSessions(
      userId,
      baseUrl,
      headers
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
   * Error recovery handler - framework handles retries by default
   * Only implement if custom recovery logic is needed
   * @param {Object} params - Original params plus error information
   * @param {Object} context - Execution context
   * @returns {Object} Recovery results
   */
  error: async (params, _context) => {
    const { error, userId } = params;
    console.error(`Session revocation failed for user ${userId}: ${error.message}`);

    // Framework handles retries for transient errors (429, 502, 503, 504)
    // Just re-throw the error to let the framework handle it
    throw error;
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