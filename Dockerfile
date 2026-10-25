# Production Dockerfile for SCADA Intrusion Detection & BB84 Quantum System
FROM python:3.12-slim

# Prevent Python from writing pyc files & enable live unbuffered stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_HOST=0.0.0.0 \
    FLASK_PORT=5000 \
    MODBUS_HOST=0.0.0.0 \
    MODBUS_PORT=5020 \
    MQTT_HOST=mqtt-broker \
    MQTT_PORT=1883

WORKDIR /app

# Install minimal system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy project source code
COPY . .

# Ensure storage directories exist
RUN mkdir -p data logs models

# Expose Web Dashboard (5000) and Modbus TCP Server (5020)
EXPOSE 5000 5020

# Container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5000/login || exit 1

# Launch main orchestrator (simulation + protocols + Flask dashboard)
CMD ["python", "main.py"]
