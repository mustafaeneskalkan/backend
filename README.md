# Node.js Express Backend Template

This is a simple backend template using Node.js, Express, MongoDB (Mongoose), JWT authentication, and rate limiting.

## Features
- User registration and login with JWT authentication
- Password hashing with bcrypt
- Email normalization and duplicate checks
- Rate limiting on authentication routes
- Environment variable support via `.env`
- MongoDB connection via Mongoose
- Ready for further API development

## Setup
1. Clone this repository.
2. Run `npm install` in the backend directory.
3. Create a `.env` file with the following:
   ```env
   MONGODB_URI=mongodb://localhost:27017/yourdbname
   JWT_SECRET=your_jwt_secret
   ```
4. Start the server:
   ```sh
   npm start
   ```

## Endpoints
- `POST /api/user/register` — Register a new user
- `POST /api/user/login` — Login and receive a JWT token

## Notes
- Adjust rate limits and JWT expiry as needed.
- Extend the user model and add more routes as your project grows.
