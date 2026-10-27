"""Hosted app: basic auth and noindex on every response (NFR4, NFR5); artifact at startup (D20)."""

import base64
import binascii
import os
import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, Response

from salesintel.app.artifact import ArtifactConfig, download, read_manifest

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
    artifact_cfg = ArtifactConfig.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # A failed download stops startup: serving without data would hide the failure.
        app.state.artifact = download(artifact_cfg) if artifact_cfg else None
        app.state.manifest = read_manifest(app.state.artifact) if app.state.artifact else {}
        yield

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

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
    def index(request: Request) -> str:
        manifest = request.app.state.manifest
        if not manifest:
            return "salesintel: up (no artifact configured)"
        lines = [f"{k}: {v}" for k, v in manifest.items()]
        return "salesintel: up\n" + "\n".join(lines)

    return app
