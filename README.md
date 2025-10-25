# Backend Template

A robust and production-ready backend template with user authentication, session management, and comprehensive security features. Built with Node.js, Express, TypeScript, and MongoDB.

## Features

### 🔐 Security & Authentication
- **JWT-based Authentication** with access and refresh tokens
- **Session Management** with multiple device support (up to 5 concurrent sessions)
- **CSRF Protection** using cookies with token validation
- **CORS Configuration** with credentials support
- **Helmet Security** headers for protection
- **Email Verification** required for sensitive operations
- **Role-based Access Control** (Admin, Writer roles)
- **Password Change Protection** (invalidates all sessions)

### 📊 Logging & Monitoring
- **Winston Logging** with structured JSON format
- **Comprehensive Debug Logs** for authentication flows
- **Request Tracking** with unique request IDs
- **Security Event Monitoring** for failed authentications
- **Performance Metrics** with operation duration tracking

### 🔧 Session Management
- **Automatic Session Cleanup** (hourly scheduled cleanup)
- **Session Statistics** for administrators
- **Device Tracking** with IP address and user agent
- **Session Termination** (single session or all sessions)
- **Session Validation** with activity updates

### 📧 Email Integration
- **Nodemailer Integration** for email verification
- **Email Templates** for user notifications
- **Verification Token System** with JWT-based tokens

## Tech Stack

- **Runtime**: Node.js with TypeScript
- **Framework**: Express.js
- **Database**: MongoDB with Mongoose ODM
- **Authentication**: JWT (jsonwebtoken)
- **Security**: Helmet, CORS, CSRF, bcryptjs
- **Logging**: Winston with Morgan
- **Email**: Nodemailer
- **Scheduling**: node-cron for cleanup tasks
- **Development**: ts-node-dev for hot reloading

## Project Structure

```
backend/
├── src/
│   ├── controllers/
│   │   └── user.ts              # User authentication & management
│   ├── middleware/
│   │   └── auth.ts              # Authentication middleware
│   ├── models/
│   │   └── user.ts              # User MongoDB schema
│   ├── routes/
│   │   ├── admin.ts             # Admin routes (sessions management)
│   │   └── user.ts              # User routes (auth, profile)
│   ├── types/
│   │   └── custom.d.ts          # TypeScript custom type definitions
│   ├── utils/
│   │   ├── db.ts                # MongoDB connection utility
│   │   ├── logger.ts            # Winston logger configuration
│   │   ├── nodemailer.ts        # Email service configuration
│   │   └── session-cleanup.ts   # Automated session cleanup
│   └── index.ts                 # Application entry point
├── logs/
│   ├── combined.log             # All application logs
│   └── error.log                # Error logs only
├── SESSION_MANAGEMENT.md        # Session management API documentation
├── package.json
├── tsconfig.json
└── README.md
```

## Installation

### Prerequisites
- Node.js (v16 or higher)
- MongoDB instance
- SMTP server for email functionality

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd backend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment Configuration**
   
   Create a `.env` file in the root directory:
   ```env
   # Server Configuration
   PORT=4000
   NODE_ENV=development
   
   # Database
   MONGODB_URI=mongodb://localhost:27017/backend
   
   # JWT Secrets (use strong, unique secrets in production)
   JWT_SECRET=your-super-secret-jwt-key-for-access-tokens
   JWT_REFRESH_SECRET=your-super-secret-jwt-key-for-refresh-tokens
   
   # CORS Configuration
   CORS_ORIGIN=http://localhost:3000
   
   # CSRF Configuration
   CSRF_COOKIE_NAME=XSRF-TOKEN
   
   # Email Configuration (using Gmail as example)
   EMAIL_USER=your-email@gmail.com
   EMAIL_PASS=your-app-specific-password
   EMAIL_FROM=noreply@yourdomain.com
   
   # Logging
   LOG_LEVEL=debug
   ```

4. **Start the development server**
   ```bash
   npm run dev
   ```

   Or build and start for production:
   ```bash
   npm run build
   npm start
   ```

## API Documentation

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/users/register` | Register new user | No |
| POST | `/api/users/login` | User login | No |
| POST | `/api/users/logout` | Logout current session | Yes |
| POST | `/api/users/logout-all` | Logout all sessions | Yes |
| POST | `/api/users/refresh-token` | Refresh access token | No |
| POST | `/api/users/verify-email` | Verify email address | No |
| POST | `/api/users/resend-verification` | Resend verification email | No |

### User Management Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/users/session` | Get current session info | Yes |
| GET | `/api/users/sessions` | Get all user sessions | Yes |
| DELETE | `/api/users/sessions/:sessionId` | Terminate specific session | Yes |

### Admin Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/admin/sessions/stats` | Get session statistics | Admin |
| POST | `/api/admin/sessions/cleanup` | Manual session cleanup | Admin |

### System Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/health` | Health check | No |
| GET | `/csrf-token` | Get CSRF token | No |

## Usage Examples

### Registration
```javascript
const response = await fetch('/api/users/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: 'johndoe',
    email: 'john@example.com',
    password: 'SecurePass123'
  })
});
```

### Login
```javascript
const response = await fetch('/api/users/login', {
  method: 'POST',
  headers: { 
    'Content-Type': 'application/json',
    'X-XSRF-TOKEN': csrfToken 
  },
  credentials: 'include',
  body: JSON.stringify({
    usernameOrEmail: 'john@example.com',
    password: 'SecurePass123'
  })
});
```

### Authenticated Request
```javascript
const response = await fetch('/api/users/session', {
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'X-Request-ID': 'unique-request-id'
  }
});
```

## Development

### Available Scripts

- `npm run dev` - Start development server with hot reloading
- `npm run build` - Build TypeScript to JavaScript
- `npm start` - Start production server
- `npm test` - Run tests (Jest)

### TypeScript Configuration

The project uses strict TypeScript configuration with:
- **Target**: ES2022
- **Module**: Node16
- **Strict Mode**: Enabled
- **Source Maps**: Generated for debugging
- **Declaration Files**: Generated for library usage

### Logging

The application features comprehensive logging:

- **Debug Level**: Detailed authentication flows and session management
- **Request Tracking**: Each request gets a unique ID for tracing
- **Security Events**: Failed authentications and permission denials
- **Performance Metrics**: Operation duration tracking

Set `LOG_LEVEL=debug` for detailed logs during development.

### Database Schema

#### User Model
```typescript
{
  username: string (unique, required)
  email: string (unique, required)
  password: string (hashed, required)
  name?: string
  role: 'Admin' | 'Writer' (default: 'Writer')
  emailVerified: boolean (default: false)
  emailVerificationToken?: string
  lastLoginAt?: Date
  passwordChangedAt: Date
  sessions: [{
    sessionId: string (uuid)
    refreshToken: string (hashed)
    expiresAt: Date
    lastActivity: Date
    userAgent?: string
    ipAddress?: string
  }]
  createdAt: Date
  updatedAt: Date
}
```

## Security Considerations

### Token Management
- **Access Tokens**: 15-minute expiration
- **Refresh Tokens**: 7-day expiration with rotation
- **Session Limits**: Maximum 5 concurrent sessions per user

### Password Security
- **bcryptjs Hashing**: Secure password storage
- **Password Change Detection**: Invalidates all sessions when password changes

### Request Security
- **CSRF Protection**: Token-based CSRF protection for state-changing operations
- **CORS Configuration**: Configurable origins with credentials support
- **Rate Limiting**: Consider implementing for production use

### Data Protection
- **Sensitive Data Exclusion**: Passwords and tokens never logged
- **Request Tracking**: Non-sensitive request metadata for debugging
- **Session Cleanup**: Automatic removal of expired sessions

## Monitoring

### Log Analysis
```bash
# Monitor failed authentications
grep "Invalid token\|Token expired" logs/combined.log

# Check session activity
grep "Session found and validated" logs/combined.log

# Monitor role permission denials
grep "Insufficient permissions" logs/combined.log
```

### Health Monitoring
```bash
# Check application health
curl http://localhost:4000/health
```

### Session Statistics (Admin)
```bash
# Get session statistics
curl -H "Authorization: Bearer <admin-token>" \
     http://localhost:4000/api/admin/sessions/stats
```

## Production Deployment

### Environment Preparation
1. **Secure Secrets**: Use strong, unique secrets for JWT tokens
2. **Database Security**: Configure MongoDB with authentication
3. **HTTPS**: Enable HTTPS for all communications
4. **Log Rotation**: Implement log rotation to manage disk space
5. **Process Management**: Use PM2 or similar for process management

### Recommended Production Settings
```env
NODE_ENV=production
LOG_LEVEL=warn
CORS_ORIGIN=https://yourdomain.com
```

### Docker Support
Consider adding Dockerfile for containerized deployment:
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY dist ./dist
EXPOSE 4000
CMD ["node", "dist/index.js"]
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit changes (`git commit -am 'Add new feature'`)
4. Push to branch (`git push origin feature/new-feature`)
5. Create Pull Request

### Development Guidelines
- Follow TypeScript strict mode requirements
- Add comprehensive logging for new features
- Include error handling for all operations
- Update documentation for API changes
- Maintain backward compatibility when possible

## License

ISC License - see package.json for details

## Author

MEK

## Support

For detailed information on specific features:
- [Session Management Documentation](./SESSION_MANAGEMENT.md)

For issues and questions, please open an issue in the repository.