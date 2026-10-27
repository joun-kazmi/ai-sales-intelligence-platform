FROM python:3.13-slim

RUN pip install --no-cache-dir uv==0.11.32
WORKDIR /srv
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev

# Render injects PORT; credentials come from env vars (never baked into the image).
ENV PORT=10000
CMD ["sh", "-c", "exec /srv/.venv/bin/uvicorn salesintel.app.main:create_app --factory --host 0.0.0.0 --port $PORT --proxy-headers"]
