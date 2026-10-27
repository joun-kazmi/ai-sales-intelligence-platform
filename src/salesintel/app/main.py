"""Hosted app. Bare version: basic auth and noindex on every response (NFR4, NFR5)."""

import base64
import binascii
import os
import secrets

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, Response

NOINDEX = {"X-Robots-Tag": "noindex, nofollow"}


def _credentials() -> tuple[str, str]:
    # Fail closed: without configured credentials the app must not start.
    user = os.environ.get("APP_USERNAME", "")
    password = os.environ.get("APP_PASSWORD", "")
    if not user or not password:
        raise RuntimeError("APP_USERNAME and APP_PASSWORD must be set")
    return user, password


def _authorized(header: str | None, user: str, password: str) -> bool:
    if not header or not header.startswith("Basic "):
        return False
    try:
        given = base64.b64decode(header[6:], validate=True).decode()
    except (binascii.Error, UnicodeDecodeError):
        return False
    given_user, sep, given_password = given.partition(":")
    if not sep:
        return False
    # Compare both parts even if the first fails, to keep timing uniform.
    user_ok = secrets.compare_digest(given_user.encode(), user.encode())
    password_ok = secrets.compare_digest(given_password.encode(), password.encode())
    return user_ok and password_ok


def create_app() -> FastAPI:
    user, password = _credentials()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def basic_auth_and_noindex(request: Request, call_next) -> Response:
        if not _authorized(request.headers.get("authorization"), user, password):
            response: Response = PlainTextResponse(
                "Authentication required",
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="salesintel"'},
            )
        else:
            response = await call_next(request)
        response.headers.update(NOINDEX)
        return response

    @app.get("/robots.txt", response_class=PlainTextResponse)
    def robots() -> str:
        return "User-agent: *\nDisallow: /\n"

    @app.get("/", response_class=PlainTextResponse)
    def index() -> str:
        return "salesintel: up"

    return app
