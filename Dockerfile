# Multi-stage build: Frontend + Backend in a single lightweight container
FROM node:20-alpine AS frontend-builder
WORKDIR /app/dashboard
COPY dashboard/package*.json ./
RUN npm install
COPY dashboard/ ./
RUN npm run build

FROM python:3.11-slim AS runtime
WORKDIR /app

# Install system utilities & python dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code, models, and SQLite database
COPY app/ ./app/
COPY scripts/ ./scripts/
COPY aegis.db ./

# Copy built frontend assets
COPY --from=frontend-builder /app/dashboard/dist ./dashboard/dist

# Expose HTTP port
EXPOSE 8000

ENV PYTHONUNBUFFERED=1
ENV API_HOST=0.0.0.0
ENV API_PORT=8000

# Seed demo events if database is empty and start FastAPI server
CMD ["python", "-m", "uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
