import os
import sys
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Request

load_dotenv()

logs_dir = Path("logs")
logs_dir.mkdir(exist_ok=True)

MODULES_TO_RELOAD_FOR_APP_FACTORY = [
    "app.auth",
    "app.models",
    "app.routers.web",
    "app.routers.api.v1.users",
    "app.routers.chat"
]

def create_app(settings_override: Optional[dict] = None) -> FastAPI:
    if settings_override:
        for key, value in settings_override.items():
            os.environ[key] = str(value)

    for module_name in MODULES_TO_RELOAD_FOR_APP_FACTORY:
        if module_name in sys.modules:
            del sys.modules[module_name]

    import app.auth
    import app.models

    from app.routers import chat, web
    from app.routers.api.v1 import users

    current_app = FastAPI(
        title="FastAPI Example",
        description="A FastAPI application with user management and OAuth2 authentication",
        version="1.0.0",
    )

    current_app.state.users_db = []
    current_app.state.next_user_id = 1
    current_app.state.chat_history = []

    current_app.include_router(web.router)
    current_app.include_router(users.router)
    current_app.include_router(chat.router)

    if os.getenv("DEBUG_MODE", "false").lower() == "true":
        @current_app.get("/debug/routes")
        async def list_routes():
            routes = []
            for route in current_app.routes:
                routes.append(
                    {
                        "path": route.path,
                        "methods": getattr(route, "methods", None),
                        "name": getattr(route, "name", None),
                    }
                )
            return routes

    return current_app

app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_config="logging.yaml")
