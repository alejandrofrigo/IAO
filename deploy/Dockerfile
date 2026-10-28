FROM python:3.12.8-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOST=0.0.0.0
WORKDIR /app
COPY pyproject.toml README.md ./
COPY apps ./apps
COPY omega ./omega
COPY web ./web
COPY docs/corpus ./docs/corpus
RUN pip install --no-cache-dir .
USER 10001:10001
EXPOSE 8080
CMD ["python", "-m", "omega.server"]
