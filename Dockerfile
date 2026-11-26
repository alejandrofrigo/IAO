# Reproducible, non-root container for external deployment qualification.
# A persistent volume and secret environment variables are mandatory at runtime.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8080 \
    IAO_STATE_DIR=/var/lib/iao \
    IAO_CORPUS_DIR=/app/knowledge

WORKDIR /app

COPY pyproject.toml README.md ./
COPY apps ./apps
COPY omega ./omega

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libgmp-dev libgmp10 \
    && apt-mark manual libgmp10 \
    && python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir '.[p2p]' \
    && apt-get purge -y --auto-remove build-essential libgmp-dev \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system iao \
    && useradd --system --gid iao --home-dir /home/iao --create-home iao \
    && mkdir -p /var/lib/iao /app/knowledge \
    && chown -R iao:iao /var/lib/iao /app

VOLUME ["/var/lib/iao"]
USER iao

EXPOSE 8080

CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8080"]
