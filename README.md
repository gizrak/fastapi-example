# FastAPI User Management API

FastAPI를 활용한 간단한 사용자 관리 API 예제 프로젝트입니다.

## 주요 기능

- 👤 **사용자 CRUD** - 사용자 생성, 조회, 수정, 삭제
- 📊 **API 문서** - Swagger UI 자동 생성
- 💾 **메모리 저장소** - 인메모리 데이터베이스 사용
- ⚡ **빠른 개발** - FastAPI의 자동 검증 및 문서화

## 빠른 시작

1. **의존성 설치**

   ```bash
   uv sync
   ```

2. **애플리케이션 실행**
   ```bash
   uvicorn main:app --reload
   ```
3. **API 접속**
   - API 서버: http://127.0.0.1:8000
   - API 문서: http://127.0.0.1:8000/docs

## API Endpoints

The API provides the following endpoints for managing users:

### User Model

```json
{
  "id": 1,
  "username": "string",
  "email": "user@example.com"
}
```

### `POST /users/`

Create a new user.

- **Request body:**
  ```json
  {
    "username": "string",
    "email": "user@example.com"
  }
  ```
- **Response body (200 OK):**
  ```json
  {
    "id": 1,
    "username": "string",
    "email": "user@example.com"
  }
  ```

### `GET /users/`

Retrieve a list of all users.

- **Response body (200 OK):**
  ```json
  [
    {
      "id": 1,
      "username": "user1",
      "email": "user1@example.com"
    },
    {
      "id": 2,
      "username": "user2",
      "email": "user2@example.com"
    }
  ]
  ```

### `GET /users/{user_id}`

Retrieve a specific user by their ID.

- **Path parameter:**
  - `user_id` (integer): The ID of the user to retrieve.
- **Response body (200 OK):**
  ```json
  {
    "id": 1,
    "username": "string",
    "email": "user@example.com"
  }
  ```
- **Response body (404 Not Found):**
  ```json
  {
    "detail": "User not found"
  }
  ```

### `PUT /users/{user_id}`

Update an existing user's information.

- **Path parameter:**
  - `user_id` (integer): The ID of the user to update.
- **Request body:**
  ```json
  {
    "username": "new_username",
    "email": "new_email@example.com"
  }
  ```
- **Response body (200 OK):**
  ```json
  {
    "id": 1,
    "username": "new_username",
    "email": "new_email@example.com"
  }
  ```
- **Response body (404 Not Found):**
  ```json
  {
    "detail": "User not found"
  }
  ```

### `DELETE /users/{user_id}`

Delete a user by their ID.

- **Path parameter:**
  - `user_id` (integer): The ID of the user to delete.
- **Response body (200 OK):**
  ```json
  {
    "message": "User deleted successfully"
  }
  ```
- **Response body (404 Not Found):**
  ```json
  {
    "detail": "User not found"
  }
  ```
