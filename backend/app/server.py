import logging
from contextlib import asynccontextmanager
from typing import Union

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes import auth, email, test_endpoints
from app.middleware.firebase_auth_middleware import FirebaseAuthMiddleware
from app.middleware.user_context_middleware import UserContextMiddleware

load_dotenv()

# we need to load env variables before initialization code runs
from . import models  # noqa: E402
from .routes import user  # noqa: E402
from .utilities.firebase_init import initialize_firebase  # noqa: E402

log = logging.getLogger("uvicorn")

# Define paths that don't require authentication
PUBLIC_PATHS = [
    "/",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/auth/login",
    "/auth/register",
    "/health"
]

@asynccontextmanager
async def lifespan(_: FastAPI):
    log.info("Starting up...")
    models.run_migrations()
    initialize_firebase()
    yield
    log.info("Shutting down...")

app = FastAPI(lifespan=lifespan)

# Add CORS middleware first
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],  # Configure this appropriately for production
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# Add our custom middleware
# Note: Middleware is executed in reverse order (last added = first executed)
app.add_middleware(
    UserContextMiddleware,
    exclude_paths=PUBLIC_PATHS
)

# app.add_middleware(
#     FirebaseAuthMiddleware,
#     exclude_paths=PUBLIC_PATHS
# )

# Source: https://stackoverflow.com/questions/77170361/
# running-alembic-migrations-on-fastapi-startup
app.include_router(auth.router)
app.include_router(user.router)
app.include_router(email.router)
app.include_router(test_endpoints.router)

@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: Union[str, None] = None):
    return {"item_id": item_id, "q": q}
