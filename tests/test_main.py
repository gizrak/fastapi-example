from fastapi.testclient import TestClient
from main import app, users_db # Import users_db to manipulate it directly for tests

client = TestClient(app)

def setup_function():
    # Clear the users_db before each test
    users_db.clear()
    # Reset the user ID counter if your app uses one (as in the example main.py)
    # This depends on how next_user_id is managed in your main.py
    # For the provided main.py, we need to reset it like this:
    import main
    main.next_user_id = 1


def test_create_user():
    setup_function()
    response = client.post("/users/", json={"username": "testuser", "email": "test@example.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"
    assert data["email"] == "test@example.com"
    assert "id" in data
    assert data["id"] == 1 # First user

def test_read_users_empty():
    setup_function()
    response = client.get("/users/")
    assert response.status_code == 200
    assert response.json() == []

def test_read_users_with_data():
    setup_function()
    client.post("/users/", json={"username": "testuser1", "email": "test1@example.com"})
    client.post("/users/", json={"username": "testuser2", "email": "test2@example.com"})
    response = client.get("/users/")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert data[0]["username"] == "testuser1"
    assert data[1]["username"] == "testuser2"

def test_read_specific_user():
    setup_function()
    response_post = client.post("/users/", json={"username": "testuser", "email": "test@example.com"})
    user_id = response_post.json()["id"]

    response_get = client.get(f"/users/{user_id}")
    assert response_get.status_code == 200
    data = response_get.json()
    assert data["username"] == "testuser"
    assert data["email"] == "test@example.com"
    assert data["id"] == user_id

def test_read_non_existent_user():
    setup_function()
    response = client.get("/users/999")
    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}

def test_update_user():
    setup_function()
    response_post = client.post("/users/", json={"username": "testuser", "email": "test@example.com"})
    user_id = response_post.json()["id"]

    response_put = client.put(f"/users/{user_id}", json={"username": "updateduser", "email": "updated@example.com"})
    assert response_put.status_code == 200
    data = response_put.json()
    assert data["username"] == "updateduser"
    assert data["email"] == "updated@example.com"
    assert data["id"] == user_id

    # Verify the update actually persisted
    response_get = client.get(f"/users/{user_id}")
    assert response_get.status_code == 200
    data_get = response_get.json()
    assert data_get["username"] == "updateduser"
    assert data_get["email"] == "updated@example.com"


def test_update_non_existent_user():
    setup_function()
    response = client.put("/users/999", json={"username": "updateduser", "email": "updated@example.com"})
    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}

def test_delete_user():
    setup_function()
    response_post = client.post("/users/", json={"username": "testuser", "email": "test@example.com"})
    user_id = response_post.json()["id"]

    response_delete = client.delete(f"/users/{user_id}")
    assert response_delete.status_code == 200
    assert response_delete.json() == {"message": "User deleted successfully"}

    # Verify the user is actually deleted
    response_get = client.get(f"/users/{user_id}")
    assert response_get.status_code == 404

def test_delete_non_existent_user():
    setup_function()
    response = client.delete("/users/999")
    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}

# Test creating multiple users and checking IDs
def test_create_multiple_users():
    setup_function()
    response1 = client.post("/users/", json={"username": "user1", "email": "user1@example.com"})
    assert response1.status_code == 200
    assert response1.json()["id"] == 1

    response2 = client.post("/users/", json={"username": "user2", "email": "user2@example.com"})
    assert response2.status_code == 200
    assert response2.json()["id"] == 2

    response_get = client.get("/users/")
    assert response_get.status_code == 200
    data = response_get.json()
    assert len(data) == 2
    assert data[0]["id"] == 1
    assert data[1]["id"] == 2
