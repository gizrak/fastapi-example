# fastapi-example

This is a sample FastAPI application demonstrating a User CRUD API.

## Setup and Running

1.  **Install dependencies:**
    ```bash
    pip install "fastapi[all]" uvicorn
    ```
    (Note: `fastapi[all]` includes `uvicorn` and other useful dependencies like `pydantic`.)

2.  **Run the application:**
    ```bash
    uvicorn main:app --reload
    ```
    The API will be available at `http://127.0.0.1:8000`.

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

*   **Request body:**
    ```json
    {
      "username": "string",
      "email": "user@example.com"
    }
    ```
*   **Response body (200 OK):**
    ```json
    {
      "id": 1,
      "username": "string",
      "email": "user@example.com"
    }
    ```

### `GET /users/`

Retrieve a list of all users.

*   **Response body (200 OK):**
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

*   **Path parameter:**
    *   `user_id` (integer): The ID of the user to retrieve.
*   **Response body (200 OK):**
    ```json
    {
      "id": 1,
      "username": "string",
      "email": "user@example.com"
    }
    ```
*   **Response body (404 Not Found):**
    ```json
    {
      "detail": "User not found"
    }
    ```

### `PUT /users/{user_id}`

Update an existing user's information.

*   **Path parameter:**
    *   `user_id` (integer): The ID of the user to update.
*   **Request body:**
    ```json
    {
      "username": "new_username",
      "email": "new_email@example.com"
    }
    ```
*   **Response body (200 OK):**
    ```json
    {
      "id": 1,
      "username": "new_username",
      "email": "new_email@example.com"
    }
    ```
*   **Response body (404 Not Found):**
    ```json
    {
      "detail": "User not found"
    }
    ```

### `DELETE /users/{user_id}`

Delete a user by their ID.

*   **Path parameter:**
    *   `user_id` (integer): The ID of the user to delete.
*   **Response body (200 OK):**
    ```json
    {
      "message": "User deleted successfully"
    }
    ```
*   **Response body (404 Not Found):**
    ```json
    {
      "detail": "User not found"
    }
    ```
