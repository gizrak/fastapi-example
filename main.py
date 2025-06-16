from dotenv import load_dotenv
from fastapi import FastAPI

from app.routers import web
from app.routers.api.v1 import users

# Load environment variables from .env file
load_dotenv()

app = FastAPI(
    title="FastAPI Example",
    description="A FastAPI application with user management and OAuth2 authentication",
    version="1.0.0",
)

# Include routers
app.include_router(web.router)  # Web pages (excluded from docs)
app.include_router(users.router)  # API endpoints (included in docs)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
