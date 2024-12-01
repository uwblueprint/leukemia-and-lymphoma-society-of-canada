import logging
from contextlib import asynccontextmanager
from typing import Union

from dotenv import load_dotenv
from fastapi import FastAPI

from app.routes import email

load_dotenv()

# we need to load env variables before initialization code runs
from . import models  # noqa: E402
from .routes import user  # noqa: E402
from .utilities.firebase_init import initialize_firebase  # noqa: E402

log = logging.getLogger("uvicorn")


@asynccontextmanager
async def lifespan(_: FastAPI):
    log.info("Starting up...")
<<<<<<< HEAD
    models.run_migrations()
    initialize_firebase()
=======
    # models.run_migrations()
>>>>>>> 99ee1d3d74b62cca4d1a5ead4e30abe191c86a3f
    yield
    log.info("Shutting down...")


# Source: https://stackoverflow.com/questions/77170361/
# running-alembic-migrations-on-fastapi-startup
app = FastAPI(lifespan=lifespan)
app.include_router(user.router)

app.include_router(email.router)


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: Union[str, None] = None):
    return {"item_id": item_id, "q": q}
