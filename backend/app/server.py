import logging
from contextlib import asynccontextmanager
from typing import Union

from dotenv import load_dotenv
from fastapi import FastAPI

from app.routes import email_test

load_dotenv()

# we need to load env variables before initialization code runs
from .routes import user  # noqa: E402
from .utilities.ses.ses_init import ensure_ses_templates  # noqa: E402

log = logging.getLogger("uvicorn")


@asynccontextmanager
async def lifespan(_: FastAPI):
    log.info("Starting up...")
    ensure_ses_templates()
    # models.run_migrations()
    # initialize_firebase()
    yield
    log.info("Shutting down...")


# Source: https://stackoverflow.com/questions/77170361/
# running-alembic-migrations-on-fastapi-startup
app = FastAPI(lifespan=lifespan)
app.include_router(user.router)
app.include_router(email_test.router)


@app.get("/")
def read_root():
    log.info("Hello World")
    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: Union[str, None] = None):
    return {"item_id": item_id, "q": q}
