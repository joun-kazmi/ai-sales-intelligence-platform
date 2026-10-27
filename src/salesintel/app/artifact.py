"""Download the scored artifact from a private GitHub Release at startup (D20, NFR3).

The artifact is one DuckDB file with at least a `manifest(key, value)` table. Render's free
disk is ephemeral, so every cold start downloads it again.
"""

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

import duckdb
import httpx

MAX_BYTES_DEFAULT = 100 * 1024 * 1024  # hard cap, NFR3
API = "https://api.github.com"


class ArtifactError(RuntimeError):
    pass


@dataclass(frozen=True)
class ArtifactConfig:
    repo: str  # owner/name
    tag: str
    name: str  # asset file name
    token: str
    dest_dir: Path
    max_bytes: int = MAX_BYTES_DEFAULT

    @classmethod
    def from_env(cls) -> "ArtifactConfig | None":
        repo = os.environ.get("ARTIFACT_REPO", "")
        if not repo:
            return None
        missing = [k for k in ("ARTIFACT_TAG", "ARTIFACT_NAME", "GITHUB_TOKEN") if not os.environ.get(k)]
        if missing:
            raise ArtifactError(f"ARTIFACT_REPO is set but {', '.join(missing)} missing")
        return cls(
            repo=repo,
            tag=os.environ["ARTIFACT_TAG"],
            name=os.environ["ARTIFACT_NAME"],
            token=os.environ["GITHUB_TOKEN"],
            dest_dir=Path(os.environ.get("ARTIFACT_DIR", tempfile.gettempdir())) / "salesintel",
            max_bytes=int(os.environ.get("ARTIFACT_MAX_BYTES", MAX_BYTES_DEFAULT)),
        )


def download(cfg: ArtifactConfig, client: httpx.Client | None = None) -> Path:
    """Fetch the release asset into cfg.dest_dir, enforcing the size cap; return its path."""
    headers = {
        "Authorization": f"Bearer {cfg.token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    # httpx drops the Authorization header when a redirect leaves api.github.com, so the token
    # is never sent to the storage host the asset download redirects to.
    own = client is None
    client = client or httpx.Client(timeout=60, follow_redirects=True)
    try:
        r = client.get(
            f"{API}/repos/{cfg.repo}/releases/tags/{cfg.tag}",
            headers={**headers, "Accept": "application/vnd.github+json"},
        )
        if r.status_code != 200:
            raise ArtifactError(f"release {cfg.tag}: HTTP {r.status_code}")
        assets = [a for a in r.json().get("assets", []) if a.get("name") == cfg.name]
        if not assets:
            raise ArtifactError(f"release {cfg.tag} has no asset {cfg.name}")
        asset = assets[0]
        if int(asset.get("size", 0)) > cfg.max_bytes:
            raise ArtifactError(f"asset is {asset['size']} bytes, over the {cfg.max_bytes} cap")

        cfg.dest_dir.mkdir(parents=True, exist_ok=True)
        target = cfg.dest_dir / cfg.name
        tmp = target.with_name(f".tmp-{target.name}")
        written = 0
        with client.stream("GET", asset["url"], headers={**headers, "Accept": "application/octet-stream"}) as resp:
            if resp.status_code != 200:
                raise ArtifactError(f"asset download: HTTP {resp.status_code}")
            with open(tmp, "wb") as fh:
                for chunk in resp.iter_bytes():
                    written += len(chunk)
                    if written > cfg.max_bytes:
                        raise ArtifactError(f"download exceeded the {cfg.max_bytes} byte cap")
                    fh.write(chunk)
        validate(tmp)
        os.replace(tmp, target)
        return target
    finally:
        tmp_path = cfg.dest_dir / f".tmp-{cfg.name}"
        tmp_path.unlink(missing_ok=True)
        if own:
            client.close()


def validate(path: Path) -> None:
    try:
        con = duckdb.connect(str(path), read_only=True)
    except duckdb.Error as e:
        raise ArtifactError(f"not a DuckDB file: {e}") from e
    try:
        con.execute("SELECT key, value FROM manifest").fetchall()
    except duckdb.Error as e:
        raise ArtifactError(f"artifact has no readable manifest table: {e}") from e
    finally:
        con.close()


def read_manifest(path: Path) -> dict[str, str]:
    con = duckdb.connect(str(path), read_only=True)
    try:
        return dict(con.execute("SELECT key, value FROM manifest ORDER BY key").fetchall())
    finally:
        con.close()
