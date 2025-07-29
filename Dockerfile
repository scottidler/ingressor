FROM python:3.12-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_NO_CACHE=1

# Create app user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Install system dependencies and uv
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && curl -LsSf https://astral.sh/uv/install.sh | sh \
    && mv /root/.cargo/bin/uv /usr/local/bin/

# Set work directory
WORKDIR /app

# Copy requirements first for better caching
COPY pyproject.toml .
COPY ingressor/ ./ingressor/

# Install Python dependencies with uv
RUN uv pip install --system -e .

# Create directories and set permissions
RUN mkdir -p /app/data && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command
CMD ["ingressor", "serve", "--host", "0.0.0.0", "--port", "8000"]
