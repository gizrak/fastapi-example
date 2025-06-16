# FastAPI Example

FastAPI application with user management, OAuth2 authentication, WebSocket chat, and web interface.

## Features

- **User CRUD API**: Complete user management with validation
- **OAuth2 Authentication**: Google OAuth2 login support
- **WebSocket Chat**: Real-time chat functionality
- **Web Interface**: HTML frontend with user management
- **JWT Token Authentication**: Secure API access
- **Docker Support**: Containerized deployment
- **Testing**: Comprehensive test suite

## Setup and Running

### Using uv (Recommended)

1. **Install dependencies:**

   ```bash
   uv sync
   ```

2. **Run the application:**
   ```bash
   uv run uvicorn main:app --reload
   ```

### Using pip

1. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

2. **Run the application:**
   ```bash
   uvicorn main:app --reload
   ```

The application will be available at:

- **Web Interface**: `http://127.0.0.1:8000`
- **API Documentation**: `http://127.0.0.1:8000/docs`
- **ReDoc**: `http://127.0.0.1:8000/redoc`

## Environment Variables

Create a `.env` file in the root directory:

```env
SECRET_KEY=your-secret-key-here
AUTH_ENABLED=true
DEBUG_MODE=false
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/callback
```

## Available Tasks

Use VS Code tasks or run directly:

```bash
# Start FastAPI server
uv run uvicorn main:app --reload

# Install dependencies
uv sync

# Run tests
uv run pytest tests/ -v

# Format code
uv run black . && uv run isort .

# Lint code
uv run flake8 .
```

## API Endpoints

### Authentication

#### `POST /token`

Get access token using OAuth2 password flow.

#### `GET /login`

Initiate Google OAuth2 login process.

#### `GET /callback`

Handle Google OAuth2 callback.

#### `GET /logout`

Logout and clear session.

### User Management

All user management endpoints require authentication (except user creation).

#### User Model

```json
{
  "id": 1,
  "username": "string",
  "email": "user@example.com",
  "hashed_password": "string"
}
```

#### UserCreate Model

```json
{
  "username": "string",
  "email": "user@example.com",
  "password": "string"
}
```

#### `POST /api/v1/users/`

Create a new user.

- **Request body:**
  ```json
  {
    "username": "testuser",
    "email": "user@example.com",
    "password": "password123"
  }
  ```
- **Response body (200 OK):**
  ```json
  {
    "id": 1,
    "username": "testuser",
    "email": "user@example.com",
    "hashed_password": "$2b$12$..."
  }
  ```

#### `GET /api/v1/users/`

Retrieve a list of all users (authentication required).

- **Headers:** `Authorization: Bearer <access_token>`
- **Response body (200 OK):**
  ```json
  [
    {
      "id": 1,
      "username": "user1",
      "email": "user1@example.com",
      "hashed_password": "$2b$12$..."
    }
  ]
  ```

#### `GET /api/v1/users/{user_id}`

Retrieve a specific user by ID (authentication required).

- **Headers:** `Authorization: Bearer <access_token>`
- **Path parameter:** `user_id` (integer)
- **Response body (200 OK):**
  ```json
  {
    "id": 1,
    "username": "testuser",
    "email": "user@example.com",
    "hashed_password": "$2b$12$..."
  }
  ```
- **Response body (404 Not Found):**
  ```json
  {
    "detail": "User not found"
  }
  ```

#### `PUT /api/v1/users/{user_id}`

Update an existing user.

- **Path parameter:** `user_id` (integer)
- **Request body:**
  ```json
  {
    "username": "new_username",
    "email": "new_email@example.com",
    "password": "new_password123"
  }
  ```
- **Response body (200 OK):**
  ```json
  {
    "id": 1,
    "username": "new_username",
    "email": "new_email@example.com",
    "hashed_password": "$2b$12$..."
  }
  ```

#### `DELETE /api/v1/users/{user_id}`

Delete a user by ID.

- **Path parameter:** `user_id` (integer)
- **Response body (200 OK):**
  ```json
  {
    "message": "User deleted successfully"
  }
  ```

#### `GET /api/v1/users` (No Authentication)

Get users without authentication (for frontend use).

### WebSocket Chat

#### `WS /ws/{token}`

WebSocket endpoint for real-time chat.

- **Path parameter:** `token` (JWT access token)
- **Connection:** Establishes WebSocket connection for authenticated user
- **Messages:** Broadcasts messages to all connected users

### Web Interface

#### `GET /`

Main page with user management interface.

#### `GET /users`

Users list page.

#### `GET /chat`

Chat interface page.

## Data Validation

### Username Requirements

- Must be alphanumeric only
- Length: 3-50 characters
- Automatically converted to lowercase

### Email Requirements

- Must be valid email format
- Uses Pydantic EmailStr validation

### Password Requirements

- Optional for user creation
- Hashed using bcrypt when provided

## Docker Support

```bash
# Build image
docker build -t fastapi-example .

# Run container
docker run -p 8000:8000 fastapi-example
```

## Testing

Run the test suite:

```bash
# Run all tests
uv run pytest tests/ -v

# Run specific test file
uv run pytest tests/test_main.py -v

# Run with coverage
uv run pytest tests/ --cov=app
```

## Development

### Project Structure

```
fastapi-example/
├── main.py                 # Application entry point
├── app/
│   ├── __init__.py
│   ├── auth.py            # Authentication logic
│   ├── models.py          # Pydantic models
│   └── routers/
│       ├── chat.py        # WebSocket chat
│       ├── web.py         # Web interface
│       └── api/v1/
│           └── users.py   # User API endpoints
├── templates/
│   └── index.html.j2      # Jinja2 templates
├── tests/                 # Test files
├── Dockerfile
└── pyproject.toml
```

### Code Quality

The project includes:

- **Black**: Code formatting
- **isort**: Import sorting
- **flake8**: Linting
- **pytest**: Testing framework

## Security Features

- **JWT Token Authentication**: Secure API access
- **Password Hashing**: bcrypt for password security
- **OAuth2 Flow**: Google authentication support
- **Environment Variables**: Secure configuration
- **Optional Authentication**: Can be disabled for development
