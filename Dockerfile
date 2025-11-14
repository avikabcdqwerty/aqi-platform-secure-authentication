# syntax=docker/dockerfile:1.4

# Use official Python image with latest stable version
FROM python:3.11-slim

# Set environment variables for security
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
        curl \
        ca-certificates \
        libssl-dev \
        build-essential \
        && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY docs/ ./docs/

# Expose port
EXPOSE 8000

# Healthcheck (optional, for container orchestrators)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl --fail https://localhost:8000/health || exit 1

# Run as non-root user for security
RUN useradd -m aqiuser
USER aqiuser

# Entrypoint: run with Uvicorn, enforce TLS if certs are present
CMD ["sh", "-c", "\
if [ -n \"$AQI_API_SSL_KEYFILE\" ] && [ -n \"$AQI_API_SSL_CERTFILE\" ]; then \
  uvicorn src.main:app --host 0.0.0.0 --port 8000 --ssl-keyfile $AQI_API_SSL_KEYFILE --ssl-certfile $AQI_API_SSL_CERTFILE; \
else \
  uvicorn src.main:app --host 0.0.0.0 --port 8000; \
fi \
"]