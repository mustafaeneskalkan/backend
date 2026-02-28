# Session Management API Documentation

This backend template includes comprehensive session management with JWT-based authentication, refresh tokens, and session cleanup.

Important: authentication is **cookie-based**. Access + refresh tokens are stored in **httpOnly cookies** and are not returned to the client as JSON tokens.

## Features

- **Secure Session Management**: Each user session is tracked with unique session IDs
- **JWT Access & Refresh Tokens**: Short-lived access tokens (15 min) with long-lived refresh tokens (7 days), stored in **httpOnly cookies**
- **Multiple Device Support**: Users can login from multiple devices with up to 5 concurrent sessions
- **Automatic Cleanup**: Expired/inactive sessions are automatically cleaned up every hour
- **Session Security**: Sessions are invalidated when password changes
- **Email Verification**: Required for sensitive operations

## CSRF + Cookies (How to call the API)

All non-GET `/api/*` endpoints use CSRF **double-submit** protection:

1) `GET /csrf-token` → server sets a non-httpOnly CSRF cookie (default: `XSRF-TOKEN`) and returns `{ csrfToken }`
2) For every `POST`/`PUT`/`DELETE` request to `/api/*`, send header `x-xsrf-token: <csrfToken>` and include cookies (`credentials: 'include'`).

Auth cookies are issued on login/register and then sent automatically:

- `accessToken` (path `/`) – used for authentication
- `refreshToken` (path `/api/users`) – used for token refresh rotation
- `sessionId` (path `/api/users`) – session identifier

## Refresh token storage

Refresh tokens are stored **hashed at rest** (HMAC). Deployments that switch from plaintext refresh tokens to hash-only validation will require users to re-login to obtain new refresh tokens.

## Environment Variables

Add these to your `.env` file:

```env
JWT_ACCESS_SECRET="your-access-token-secret"
JWT_REFRESH_SECRET="your-refresh-token-secret"

# Optional: use a separate secret for email verification tokens
JWT_EMAIL_VERIFY_SECRET="your-email-verification-secret"

# Optional: use a separate secret for password reset tokens
JWT_PASSWORD_RESET_SECRET="your-password-reset-secret"

# Optional: secret used to HMAC-hash refresh tokens at rest (falls back to JWT_REFRESH_SECRET)
REFRESH_TOKEN_HASH_SECRET="your-refresh-token-hash-secret"

# Optional: session limits
MAX_ACTIVE_SESSIONS_PER_USER=5

# Optional: throttle session lastActivity DB writes
SESSION_ACTIVITY_THROTTLE_SECONDS=300

# Required for email links
FRONTEND_URL="http://localhost:3000"

# Optional: cookie config
# COOKIE_SAME_SITE=lax|strict|none
# COOKIE_SECURE=true|false
# COOKIE_DOMAIN=example.com

# Optional: override cookie names
# CSRF_COOKIE_NAME=XSRF-TOKEN
# ACCESS_TOKEN_COOKIE_NAME=accessToken
# REFRESH_TOKEN_COOKIE_NAME=refreshToken
# SESSION_ID_COOKIE_NAME=sessionId

# Optional: only allow /api/admin/auth/* from this origin
# CMS_ORIGIN="https://cms.example.com"
```

## Request IDs

The server generates a request id for every request and returns it in the `x-request-id` response header.
Clients may also provide `X-Request-ID`; the server will propagate it.

## API Endpoints

Unless stated otherwise, all `POST`/`DELETE` routes below require the CSRF header `x-xsrf-token` and cookies.

### Authentication Routes

#### POST `/api/users/register`
Register a new user account.

**Request Body:**
```json
{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "SecurePass123"
}
```

**Response:**
```json
{
  "message": "User registered successfully. Please check your email for verification.",
  "user": {
    "id": "user_id",
    "username": "johndoe",
    "email": "john@example.com",
    "emailVerified": false
  },
  "session": {
    "sessionId": "uuid-session-id",
    "expiresIn": 900
  }
}
```

#### POST `/api/users/login`
Login with username/email and password.

**Request Body:**
```json
{
  "usernameOrEmail": "john@example.com",
  "password": "SecurePass123"
}
```

**Response:**
```json
{
  "message": "Login successful",
  "user": {
    "id": "user_id",
    "username": "johndoe",
    "email": "john@example.com",
    "name": "John Doe",
    "role": "Writer",
    "emailVerified": true,
    "lastLoginAt": "2025-10-05T10:30:00.000Z"
  },
  "session": {
    "sessionId": "uuid-session-id",
    "expiresIn": 900
  }
}
```

#### POST `/api/users/refresh-token`
Refresh access token using refresh token.

No request body is required. The server reads `refreshToken` + `sessionId` from httpOnly cookies and rotates them.

**Response:**
```json
{
  "message": "Token refreshed successfully",
  "session": {
    "sessionId": "uuid-session-id",
    "expiresIn": 900
  }
}
```

### Session Management Routes (Require Authentication)

#### POST `/api/users/logout`
Logout from current session.

Requires a valid `accessToken` cookie.

**Response:**
```json
{
  "message": "Logout successful"
}
```

#### POST `/api/users/logout-all`
Logout from all sessions.

Requires a valid `accessToken` cookie.

**Response:**
```json
{
  "message": "Logged out from all sessions successfully"
}
```

#### GET `/api/users/session`
Get current session information.

Requires a valid `accessToken` cookie.

**Response:**
```json
{
  "user": {
    "id": "user_id",
    "username": "johndoe",
    "email": "john@example.com",
    "name": "John Doe",
    "role": "Writer",
    "emailVerified": true,
    "lastLoginAt": "2025-10-05T10:30:00.000Z",
    "createdAt": "2025-10-01T10:30:00.000Z"
  },
  "session": {
    "sessionId": "uuid-session-id",
    "lastActivity": "2025-10-05T10:35:00.000Z",
    "userAgent": "Mozilla/5.0...",
    "ipAddress": "192.168.1.100"
  }
}
```

#### GET `/api/users/sessions`
Get all active sessions for the user.

Requires a valid `accessToken` cookie.

**Response:**
```json
{
  "sessions": [
    {
      "sessionId": "uuid-session-id-1",
      "lastActivity": "2025-10-05T10:35:00.000Z",
      "userAgent": "Mozilla/5.0 (Windows...)",
      "ipAddress": "192.168.1.100",
      "isCurrent": true
    },
    {
      "sessionId": "uuid-session-id-2",
      "lastActivity": "2025-10-05T09:20:00.000Z",
      "userAgent": "Mozilla/5.0 (iPhone...)",
      "ipAddress": "192.168.1.101",
      "isCurrent": false
    }
  ],
  "total": 2
}
```

#### DELETE `/api/users/sessions/:sessionId`
Terminate a specific session.

Requires a valid `accessToken` cookie and CSRF.

**Response:**
```json
{
  "message": "Session terminated successfully"
}
```

### Email Verification Routes

#### POST `/api/users/verify-email`
Verify email address with token.

**Request Body:**
```json
{
  "token": "verification-jwt-token"
}
```

**Response:**
```json
{
  "message": "Email verified successfully",
  "user": {
    "id": "user_id",
    "username": "johndoe",
    "email": "john@example.com",
    "emailVerified": true
  }
}
```

#### POST `/api/users/resend-verification`
Resend email verification.

**Request Body:**
```json
{
  "email": "john@example.com"
}
```

**Response:**
```json
{
  "message": "Verification email sent successfully"
}
```

### Email Change Routes

This backend implements a two-step email change:
1) authenticated user requests the change (stores a **pending email** + sends a verification token)
2) frontend submits the token to the backend to finalize the change

#### POST `/api/users/change-email`
Request an email change. The account email is **not** changed until verification succeeds.

Requires a valid `accessToken` cookie, CSRF, and a verified email (`EMAIL_NOT_VERIFIED` otherwise).

**Request Body:**
```json
{
  "newEmail": "newaddress@example.com"
}
```

**Response:**
```json
{
  "message": "Email change verification sent"
}
```

#### POST `/api/users/verify-email-change`
Verify the email change token and finalize the email update.

Requires CSRF.

**Request Body:**
```json
{
  "token": "verification-jwt-token"
}
```

**Response:**
```json
{
  "message": "Email changed and verified successfully",
  "user": {
    "id": "user_id",
    "username": "johndoe",
    "email": "newaddress@example.com",
    "emailVerified": true
  }
}
```

### Admin Routes (Require Admin Role)

Admin auth is also cookie-based.

#### POST `/api/admin/auth/login`
Login as an admin user.

If `CMS_ORIGIN` is set, requests must originate from that origin (otherwise you’ll get `CMS_ORIGIN_BLOCKED`).

#### GET `/api/admin/sessions/stats`
Get session statistics.

Requires a valid `accessToken` cookie for an `Admin` user.

**Response:**
```json
{
  "totalUsers": 150,
  "usersWithActiveSessions": 45,
  "totalActiveSessions": 72,
  "expiredSessions": 25
}
```

#### POST `/api/admin/sessions/cleanup`
Manually trigger session cleanup.

Requires a valid `accessToken` cookie for an `Admin` user and CSRF.

**Response:**
```json
{
  "message": "Session cleanup completed successfully"
}
```

## Client Implementation

### Frontend Usage Example

```javascript
class AuthService {
  constructor() {
    this.csrfToken = null;
  }

  async getCSRFToken() {
    if (this.csrfToken) return this.csrfToken;
    const res = await fetch('/csrf-token', { credentials: 'include' });
    const data = await res.json();
    this.csrfToken = data.csrfToken;
    return this.csrfToken;
  }

  async login(usernameOrEmail, password) {
    const response = await fetch('/api/users/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-xsrf-token': await this.getCSRFToken()
      },
      credentials: 'include',
      body: JSON.stringify({ usernameOrEmail, password })
    });

    if (response.ok) {
      const data = await response.json();
      return data;
    }
    throw new Error('Login failed');
  }

  async refreshAccessToken() {
    const response = await fetch('/api/users/refresh-token', {
      method: 'POST',
      headers: {
        'x-xsrf-token': await this.getCSRFToken(),
      },
      credentials: 'include',
    });

    if (!response.ok) throw new Error('Token refresh failed');
    return response.json();
  }

  async apiCall(url, options = {}) {
    let response = await fetch(url, {
      ...options,
      credentials: 'include',
      headers: { ...options.headers }
    });

    // If access cookie expired, refresh and retry once
    if (response.status === 401) {
      await this.refreshAccessToken();
      response = await fetch(url, {
        ...options,
        credentials: 'include',
        headers: { ...options.headers }
      });
    }

    return response;
  }
}
```

## Security Features

1. **Short-lived Access Tokens**: 15-minute expiration reduces token hijacking risks
2. **Refresh Token Rotation**: New refresh tokens issued on each refresh
3. **Session Validation**: All requests validate session existence and activity
4. **Automatic Cleanup**: Expired sessions removed hourly
5. **Password Change Protection**: All sessions invalidated when password changes
6. **IP & User Agent Tracking**: Sessions track device information
7. **Session Limits**: Maximum 5 concurrent sessions per user
8. **CSRF Protection**: All state-changing endpoints protected
9. **Email Verification**: Required for account security

## Error Codes

Common error codes returned by the authentication system:

- `NO_TOKEN`: No access token provided
- `TOKEN_INVALID`: Invalid or malformed token
- `TOKEN_EXPIRED`: Access token has expired
- `SESSION_INVALID`: Session not found or inactive
- `USER_NOT_FOUND`: User account doesn't exist
- `PASSWORD_CHANGED`: Password changed after token issued
- `EMAIL_NOT_VERIFIED`: Email verification required
- `INSUFFICIENT_PERMISSIONS`: User lacks required role
- `CSRF_INVALID`: Missing/invalid CSRF double-submit token
- `MISSING_REFRESH_DATA`: Missing refresh cookies
- `REFRESH_SESSION_MISMATCH`: Refresh token sessionId mismatch
- `REFRESH_SESSION_INVALID`: Invalid refresh session (not found / hash mismatch)
- `REFRESH_TOKEN_INVALID`: Invalid refresh token
- `REFRESH_TOKEN_EXPIRED`: Refresh token has expired
- `CMS_ORIGIN_BLOCKED`: Admin auth request blocked by `CMS_ORIGIN`

## Migration from Old System

If you had a simple JWT system before:

1. **Database Migration**: Users will need to login again to create sessions
2. **Client Updates**: Update frontend to use cookie-based auth + CSRF (`/csrf-token` + `x-xsrf-token`)
3. **Token Validation**: All existing tokens will be invalid
4. **Environment**: Ensure `JWT_ACCESS_SECRET` and `JWT_REFRESH_SECRET` are set

## Monitoring

Monitor your session system with:

```javascript
// Check session statistics
const stats = await fetch('/api/admin/sessions/stats', { credentials: 'include' });

console.log(await stats.json());
// {
//   totalUsers: 150,
//   usersWithActiveSessions: 45,
//   totalActiveSessions: 72,
//   expiredSessions: 25
// }
```