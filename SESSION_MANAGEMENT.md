# Session Management API Documentation

This backend template includes comprehensive session management with JWT-based authentication, refresh tokens, and session cleanup.

## Features

- **Secure Session Management**: Each user session is tracked with unique session IDs
- **JWT Access & Refresh Tokens**: Short-lived access tokens (15 min) with long-lived refresh tokens (7 days)
- **Multiple Device Support**: Users can login from multiple devices with up to 5 concurrent sessions
- **Automatic Cleanup**: Expired sessions are automatically cleaned up every hour
- **Session Security**: Sessions are invalidated when password changes
- **Email Verification**: Required for sensitive operations

## Environment Variables

Add these to your `.env` file:

```env
JWT_SECRET="your-access-token-secret"
JWT_REFRESH_SECRET="your-refresh-token-secret"
```

## API Endpoints

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
    "accessToken": "jwt-access-token",
    "refreshToken": "jwt-refresh-token",
    "expiresIn": 900
  }
}
```

#### POST `/api/users/refresh-token`
Refresh access token using refresh token.

**Request Body:**
```json
{
  "refreshToken": "current-refresh-token",
  "sessionId": "current-session-id"
}
```

**Response:**
```json
{
  "message": "Token refreshed successfully",
  "session": {
    "sessionId": "uuid-session-id",
    "accessToken": "new-jwt-access-token",
    "refreshToken": "new-jwt-refresh-token",
    "expiresIn": 900
  }
}
```

### Session Management Routes (Require Authentication)

#### POST `/api/users/logout`
Logout from current session.

**Headers:**
```
Authorization: Bearer <access-token>
```

**Response:**
```json
{
  "message": "Logout successful"
}
```

#### POST `/api/users/logout-all`
Logout from all sessions.

**Headers:**
```
Authorization: Bearer <access-token>
```

**Response:**
```json
{
  "message": "Logged out from all sessions successfully"
}
```

#### GET `/api/users/session`
Get current session information.

**Headers:**
```
Authorization: Bearer <access-token>
```

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

**Headers:**
```
Authorization: Bearer <access-token>
```

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

**Headers:**
```
Authorization: Bearer <access-token>
```

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

### Admin Routes (Require Admin Role)

#### GET `/api/admin/sessions/stats`
Get session statistics.

**Headers:**
```
Authorization: Bearer <admin-access-token>
```

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

**Headers:**
```
Authorization: Bearer <admin-access-token>
```

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
    this.accessToken = localStorage.getItem('accessToken');
    this.refreshToken = localStorage.getItem('refreshToken');
    this.sessionId = localStorage.getItem('sessionId');
  }

  async login(usernameOrEmail, password) {
    const response = await fetch('/api/users/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-XSRF-TOKEN': await this.getCSRFToken()
      },
      credentials: 'include',
      body: JSON.stringify({ usernameOrEmail, password })
    });

    if (response.ok) {
      const data = await response.json();
      this.setTokens(data.session);
      return data;
    }
    throw new Error('Login failed');
  }

  async refreshAccessToken() {
    try {
      const response = await fetch('/api/users/refresh-token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-XSRF-TOKEN': await this.getCSRFToken()
        },
        credentials: 'include',
        body: JSON.stringify({
          refreshToken: this.refreshToken,
          sessionId: this.sessionId
        })
      });

      if (response.ok) {
        const data = await response.json();
        this.setTokens(data.session);
        return data.session.accessToken;
      }
      
      this.logout();
      throw new Error('Token refresh failed');
    } catch (error) {
      this.logout();
      throw error;
    }
  }

  async apiCall(url, options = {}) {
    let token = this.accessToken;
    
    // Try the request with current token
    let response = await fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${token}`
      }
    });

    // If token expired, try to refresh
    if (response.status === 401) {
      token = await this.refreshAccessToken();
      response = await fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          'Authorization': `Bearer ${token}`
        }
      });
    }

    return response;
  }

  setTokens(session) {
    this.accessToken = session.accessToken;
    this.refreshToken = session.refreshToken;
    this.sessionId = session.sessionId;
    
    localStorage.setItem('accessToken', session.accessToken);
    localStorage.setItem('refreshToken', session.refreshToken);
    localStorage.setItem('sessionId', session.sessionId);
  }

  logout() {
    this.accessToken = null;
    this.refreshToken = null;
    this.sessionId = null;
    
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('sessionId');
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
- `REFRESH_TOKEN_EXPIRED`: Refresh token has expired
- `REFRESH_SESSION_INVALID`: Invalid refresh session

## Migration from Old System

If you had a simple JWT system before:

1. **Database Migration**: Users will need to login again to create sessions
2. **Client Updates**: Update frontend to handle refresh tokens
3. **Token Validation**: All existing tokens will be invalid
4. **Environment**: Add `JWT_REFRESH_SECRET` to your environment

## Monitoring

Monitor your session system with:

```javascript
// Check session statistics
const stats = await fetch('/api/admin/sessions/stats', {
  headers: { 'Authorization': `Bearer ${adminToken}` }
});

console.log(await stats.json());
// {
//   totalUsers: 150,
//   usersWithActiveSessions: 45,
//   totalActiveSessions: 72,
//   expiredSessions: 25
// }
```