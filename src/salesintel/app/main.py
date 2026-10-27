"""Hosted app: basic auth and noindex on every response (NFR4, NFR5); artifact at startup (D20).

Pages per docs/design/ui.md: ranked list with filters, account detail, plays, CSV export.
"""

import base64
import binascii
import csv
import io
import math
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlencode

import jinja2
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.templating import Jinja2Templates

from salesintel.app.artifact import ArtifactConfig, download
from salesintel.app.store import (ELIGIBILITY, GEAR, PLAYS, TIERS, WHY_NOW, WHY_NOW_TEXT, BadFilter, Filters,
                                  Store)

NOINDEX = {"X-Robots-Tag": "noindex, nofollow"}
SOURCE_TEXT = {"scan_hostname": "scanned by name", "cert_cn": "TLS certificate name",
               "http_host": "HTTP host name", "ptr": "reverse DNS name"}
OPTIONS = {
    "tier": [("ranked", "ranked (1-3)"), ("1", "1"), ("2", "2"), ("3", "3"), ("all", "all incl. unranked")],
    "play": [("", "any")] + [(k, v[0]) for k, v in PLAYS.items()],
    "why_now": [("", "any or none"), ("any", "has why-now")] + [(k, v) for k, v in WHY_NOW_TEXT.items()],
    "gear": [("", "any"), ("appliance", "edge appliance"), ("cdn", "behind CDN / WAF"), ("none", "neither")],
    "eligibility": [("default", "hide likely non-prospects"), ("likely_org", "likely organisations only"),
                    ("all", "all")],
}
assert {k for k, _ in OPTIONS["tier"]} == set(TIERS) and {k for k, _ in OPTIONS["eligibility"]} == set(ELIGIBILITY)
assert set(GEAR) | {""} == {k for k, _ in OPTIONS["gear"]} and set(WHY_NOW) <= {k for k, _ in OPTIONS["why_now"]}

_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(Path(__file__).with_name("templates")),
    autoescape=True,  # every record-derived string is untrusted (NFR5)
)
templates = Jinja2Templates(env=_env)


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
    local = os.environ.get("ARTIFACT_PATH")  # local runs and tests: skip the release download
    artifact_cfg = None if local else ArtifactConfig.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # A failed download stops startup: serving without data would hide the failure.
        path = Path(local) if local else (download(artifact_cfg) if artifact_cfg else None)
        app.state.store = Store(path) if path else None
        app.state.manifest = app.state.store.manifest() if path else {}
        app.state.summary = app.state.store.summary() if path else {}
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

    def store(request: Request) -> Store:
        s = request.app.state.store
        if s is None:
            raise HTTPException(503, "no artifact configured")
        return s

    def filters(request: Request) -> Filters:
        try:
            return Filters.parse(dict(request.query_params))
        except BadFilter as e:
            raise HTTPException(400, str(e)) from e

    @app.get("/robots.txt", response_class=PlainTextResponse)
    def robots() -> str:
        return "User-agent: *\nDisallow: /\n"

    @app.get("/", response_model=None)
    def index(request: Request) -> Response:
        if request.app.state.store is None:
            return PlainTextResponse("salesintel: up (no artifact configured)")
        s, f = store(request), filters(request)
        try:
            page = max(1, int(request.query_params.get("page", "1")))
        except ValueError as e:
            raise HTTPException(400, "bad page") from e
        total = s.count(f)
        pages = max(1, math.ceil(total / 50))
        page = min(page, pages)
        rows = s.page(f, page)
        return templates.TemplateResponse(request, "list.html", {
            "m": request.app.state.manifest, "sm": request.app.state.summary, "rows": rows,
            "tags": s.tags([a["domain"] for a in rows]), "total": total, "page": page,
            "pages": pages, "f": f.__dict__, "play": f.play, "plays": PLAYS, "options": OPTIONS,
            "why_text": WHY_NOW_TEXT, "export_qs": urlencode(f.query()),
            "prev_qs": urlencode(f.query(page=page - 1)), "next_qs": urlencode(f.query(page=page + 1)),
        })

    @app.get("/account/{domain}", response_class=HTMLResponse)
    def account(request: Request, domain: str) -> Response:
        a, findings = store(request).account(domain)
        if a is None:
            raise HTTPException(404, "unknown account")
        sections = [
            ("Scored findings", [x for x in findings if x["points"] > 0]),
            ("Also observed (0 points)", [x for x in findings if x["points"] == 0 and x["family"] not in ("why_now", "fact")]),
            ("Why now (markers, 0 points)", [x for x in findings if x["family"] == "why_now"]),
            ("Facts (0 points; for plays and filters)", [x for x in findings if x["family"] == "fact"]),
        ]
        return templates.TemplateResponse(request, "account.html", {
            "m": request.app.state.manifest, "sm": request.app.state.summary, "a": a, "sections": sections, "source_text": SOURCE_TEXT})

    @app.get("/plays", response_class=HTMLResponse)
    def plays(request: Request) -> Response:
        return templates.TemplateResponse(request, "plays.html", {
            "m": request.app.state.manifest, "sm": request.app.state.summary, "plays": PLAYS, "counts": store(request).play_counts()})

    @app.get("/export.csv")
    def export(request: Request) -> StreamingResponse:
        s, f = store(request), filters(request)

        def rows():
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["rank", "domain", "score", "tier", "eligibility", "link_confidence", "why_now", "reasons"])
            for a in s.iter_all(f):
                w.writerow([a["rank"], a["domain"], a["score"], a["tier"], a["eligibility"], a["attribution_label"],
                            " / ".join(a["why_now"]), " / ".join(a["reasons"])])
                if buf.tell() > 64_000:
                    yield buf.getvalue()
                    buf.seek(0)
                    buf.truncate()
            yield buf.getvalue()

        return StreamingResponse(rows(), media_type="text/csv",
                                 headers={"Content-Disposition": 'attachment; filename="accounts.csv"'})

    return app
