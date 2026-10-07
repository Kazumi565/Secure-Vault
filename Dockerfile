FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --uid 10001 --create-home vault \
    && mkdir -p /app/data && chown vault:vault /app/data
COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./
USER vault
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/readyz', timeout=5)"
CMD ["sh", "-c", "python -m app.manage upgrade && exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000 --no-access-log"]
