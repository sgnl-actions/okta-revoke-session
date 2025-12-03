# Okta Revoke Session Action

Revoke all active sessions for an Okta user, forcing them to re-authenticate. This is commonly used for security incidents or when user credentials may be compromised.

## Overview

This SGNL action integrates with Okta to revoke all active sessions for a specified user. When executed, the user will be logged out of all devices and applications, requiring them to re-authenticate.

## Prerequisites

- Okta instance
- API authentication credentials (supports 4 auth methods - see Configuration below)
- Okta API access with permissions to revoke user sessions

## Configuration

### Authentication

This action supports four authentication methods. Configure one of the following:

#### Option 1: Bearer Token (Okta API Token)
| Secret | Description |
|--------|-------------|
| `BEARER_AUTH_TOKEN` | Okta API token (SSWS format) |

#### Option 2: Basic Authentication
| Secret | Description |
|--------|-------------|
| `BASIC_USERNAME` | Username for Okta authentication |
| `BASIC_PASSWORD` | Password for Okta authentication |

#### Option 3: OAuth2 Client Credentials
| Secret/Environment | Description |
|-------------------|-------------|
| `OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET` | OAuth2 client secret |
| `OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID` | OAuth2 client ID |
| `OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL` | OAuth2 token endpoint URL |
| `OAUTH2_CLIENT_CREDENTIALS_SCOPE` | OAuth2 scope (optional) |
| `OAUTH2_CLIENT_CREDENTIALS_AUDIENCE` | OAuth2 audience (optional) |
| `OAUTH2_CLIENT_CREDENTIALS_AUTH_STYLE` | OAuth2 auth style (optional) |

#### Option 4: OAuth2 Authorization Code
| Secret | Description |
|--------|-------------|
| `OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN` | OAuth2 access token |

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `ADDRESS` | Okta API base URL | `https://dev-12345.okta.com` |

### Input Parameters

| Parameter | Type | Required | Description | Example |
|-----------|------|----------|-------------|---------|
| `userId` | string | Yes | The Okta user ID | `00u1234567890abcdef` |
| `address` | string | No | Okta API base URL (overrides ADDRESS environment variable) | `https://dev-12345.okta.com` |

### Output Structure

| Field | Type | Description |
|-------|------|-------------|
| `userId` | string | The user ID that was processed |
| `sessionsRevoked` | boolean | Whether sessions were successfully revoked |
| `address` | string | The Okta API base URL used |
| `revokedAt` | datetime | When the operation completed (ISO 8601) |

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
    "userId": "00u1234567890abcdef"
  },
  "environment": {
    "ADDRESS": "https://dev-12345.okta.com"
  }
}
```

### Successful Response

```json
{
  "userId": "00u1234567890abcdef",
  "sessionsRevoked": true,
  "address": "https://dev-12345.okta.com",
  "revokedAt": "2024-01-15T10:30:00Z"
}
```

## How It Works

The action performs a DELETE request to the Okta API to revoke all active sessions for the specified user:

1. **Validate Input**: Ensures userId parameter is provided
2. **Authenticate**: Uses configured authentication method to get authorization
3. **Revoke Sessions**: Makes DELETE request to `/api/v1/users/{userId}/sessions`
4. **Return Result**: Confirms sessions were revoked

## Error Handling

The action includes error handling for common scenarios:

### HTTP Status Codes
- **204 No Content**: Successful session revocation (expected response)
- **400 Bad Request**: Invalid user ID format
- **401 Unauthorized**: Invalid authentication credentials
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: User not found
- **429 Rate Limit**: Too many requests

## Development

### Local Testing

```bash
# Install dependencies
npm install

# Run tests
npm test

# Test locally with mock data
npm run dev

# Build for production
npm run build
```

### Running Tests

The action includes comprehensive unit tests covering:
- Input validation (userId parameter)
- Authentication handling (all 4 auth methods)
- Success scenarios
- Error handling (API errors, missing credentials)

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Check test coverage
npm run test:coverage
```

## Security Considerations

- **Credential Protection**: Never log or expose authentication credentials
- **Session Impact**: Revoking sessions immediately logs users out of all devices
- **Audit Logging**: All operations are logged with timestamps
- **Input Validation**: userId parameter is validated and URL-encoded

## Okta API Reference

This action uses the following Okta API endpoint:
- [Clear User Sessions](https://developer.okta.com/docs/reference/api/users/#clear-user-sessions) - DELETE `/api/v1/users/{userId}/sessions`

## Troubleshooting

### Common Issues

1. **"Invalid or missing userId parameter"**
   - Ensure the `userId` parameter is provided and is a non-empty string
   - Verify the user ID exists in your Okta instance

2. **"No authentication configured"**
   - Ensure you have configured one of the four supported authentication methods
   - Check that the required secrets/environment variables are set

3. **"Failed to revoke sessions: HTTP 404"**
   - Verify the user ID is correct
   - Check that the user exists in Okta

4. **"Failed to revoke sessions: HTTP 401"**
   - Verify your authentication credentials are correct
   - Check that the API token or OAuth credentials are not expired

5. **"Failed to revoke sessions: HTTP 403"**
   - Ensure your API credentials have permission to revoke user sessions
   - Check Okta admin console for required permissions

## License

MIT

## Support

For issues or questions, please contact SGNL Engineering or create an issue in this repository.
