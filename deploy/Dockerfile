FROM python:3.12.8-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOST=0.0.0.0 PORT=8080 HOME=/var/lib/iao/home OMEGA_STATE_DIR=/var/lib/iao IAO_STATE_DIR=/var/lib/iao OMEGA_CORPUS_DIR=/app/docs/corpus IAO_CORPUS_DIR=/app/docs/corpus
WORKDIR /app
COPY pyproject.toml README.md ./
COPY apps ./apps
COPY omega ./omega
COPY web ./web
COPY docs/corpus ./docs/corpus
RUN pip install --no-cache-dir . \
    && mkdir -p /var/lib/iao/home \
    && chown -R 10001:10001 /var/lib/iao
VOLUME ["/var/lib/iao"]
USER 10001:10001
EXPOSE 8080
CMD ["python", "-m", "omega.server"]
