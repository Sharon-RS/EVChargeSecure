# Secure Multi-Stage / Hardened Dockerfile for EVChargeSecure
# Base image: Official lightweight Python 3.12 Slim
FROM python:3.12-slim AS runtime

# Security: Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000 \
    HOST=0.0.0.0 \
    FLASK_ENV=production \
    DATABASE_PATH=/app/data/evcharge_secure.db

# Security: Install only minimal OS updates and clean up in single layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install dependencies before copying source code for optimal Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY app/ app/
COPY run.py seed_data.py ./

# Security: Create dedicated unprivileged user and group (Least Privilege)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/bash -m appuser && \
    mkdir -p /app/data && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER 10001:10001

# Expose controlled service port
EXPOSE 5000

# Health Check ensuring application readiness
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/auth/login').getcode() == 200 or exit(1)"

# Start application server
CMD ["python", "run.py"]
