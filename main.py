from dotenv import load_dotenv
from fastapi import FastAPI

from app.routers import chat, web
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
app.include_router(chat.router)  # Chat WebSocket endpoints


# Debug endpoint to list all routes
@app.get("/debug/routes")
async def list_routes():
    routes = []
    for route in app.routes:
        routes.append(
            {
                "path": route.path,
                "methods": getattr(route, "methods", None),
                "name": getattr(route, "name", None),
            }
        )
    return routes


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
