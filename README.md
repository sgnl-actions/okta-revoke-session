# Okta Revoke Session Action

Revoke all active sessions for an Okta user, forcing them to re-authenticate. This action is commonly used for security incidents or when user credentials may be compromised.

## Overview

This SGNL action integrates with Okta's REST API to immediately terminate all active sessions for a specified user. When executed, the user will be logged out of all Okta applications and will need to re-authenticate.

## Prerequisites

- Okta API Token with appropriate permissions
- Okta domain (e.g., `example.okta.com`)
- Target user's Okta user ID

## Configuration

### Required Secrets

- `OKTA_API_TOKEN` - Your Okta API token (can be prefixed with "SSWS " or provided without prefix)

### Optional Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_BACKOFF_MS` | `30000` | Wait time after rate limit (429) errors |
| `SERVICE_ERROR_BACKOFF_MS` | `10000` | Wait time after service errors (502/503/504) |

### Input Parameters

| Parameter | Type | Required | Description | Example |
|-----------|------|----------|-------------|---------|
| `userId` | string | Yes | The Okta user ID whose sessions should be revoked | `00u1a2b3c4d5e6f7g8h9` |
| `oktaDomain` | string | Yes | Your Okta domain | `example.okta.com` |

### Output Structure

| Field | Type | Description |
|-------|------|-------------|
| `userId` | string | The user ID whose sessions were revoked |
| `sessionsRevoked` | boolean | Whether sessions were successfully revoked |
| `oktaDomain` | string | The Okta domain where the action was performed |
| `revokedAt` | datetime | When the sessions were revoked (ISO 8601) |

## Usage Example

### Job Request

```json
{
  "id": "revoke-session-001",
  "type": "nodejs-22",
  "script": {
    "repository": "github.com/sgnl-actions/okta-revoke-session",
    "version": "v1.0.0",
    "type": "nodejs"
  },
  "script_inputs": {
    "userId": "00u1a2b3c4d5e6f7g8h9",
    "oktaDomain": "example.okta.com"
  },
  "environment": {
    "LOG_LEVEL": "info"
  }
}
```

### Successful Response

```json
{
  "userId": "00u1a2b3c4d5e6f7g8h9",
  "sessionsRevoked": true,
  "oktaDomain": "example.okta.com",
  "revokedAt": "2024-01-15T10:30:00Z"
}
```

## Error Handling

The action includes automatic retry logic for common transient errors:

### Retryable Errors
- **429 Rate Limit**: Waits 30 seconds before retrying
- **502/503/504 Service Issues**: Waits 10 seconds before retrying

### Non-Retryable Errors
- **401 Unauthorized**: Invalid API token
- **404 Not Found**: User doesn't exist
- **400 Bad Request**: Invalid parameters

## Development

### Local Testing

```bash
# Install dependencies
npm install

# Run tests
npm test

# Test locally with mock data
npm run dev -- --params '{"userId": "test123", "oktaDomain": "dev.okta.com"}'

# Build for production
npm run build
```

### Running Tests

The action includes comprehensive unit tests covering:
- Successful session revocation
- API token validation
- Error response handling
- Retry logic for rate limiting
- Service interruption recovery

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Check test coverage
npm run test:coverage
```

## Security Considerations

- **API Token Protection**: Never log or expose the Okta API token
- **Audit Logging**: All session revocations are logged with timestamps
- **Idempotent Operations**: Safe to retry if network issues occur
- **Input Validation**: Domain format is validated via regex pattern

## Okta API Reference

This action uses the following Okta API endpoint:
- [Clear User Sessions](https://developer.okta.com/docs/reference/api/users/#clear-user-sessions)

## Troubleshooting

### Common Issues

1. **"Missing required secret: OKTA_API_TOKEN"**
   - Ensure the `OKTA_API_TOKEN` secret is configured in your SGNL environment

2. **"Not found: Resource not found"**
   - Verify the user ID exists in your Okta organization
   - Check that the user ID format is correct

3. **"Invalid API token"**
   - Confirm your API token has the necessary permissions
   - Verify the token hasn't expired

4. **Rate Limiting**
   - The action automatically handles rate limits with backoff
   - Consider batching operations if revoking many sessions

## Version History

### v1.0.0
- Initial release
- Support for session revocation via Okta API
- Automatic retry logic for transient errors
- Comprehensive error handling and logging

## License

MIT

## Support

For issues or questions, please contact SGNL Engineering or create an issue in this repository.