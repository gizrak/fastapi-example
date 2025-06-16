# Use Python 3.12 slim image as base
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install uv
RUN pip install uv

# Copy dependency files
COPY pyproject.toml uv.lock* ./

# Install dependencies using uv
RUN uv sync --frozen

# Copy application code
COPY . .

# Expose port 8000
EXPOSE 8000

# Create logs directory
RUN mkdir -p logs

# Run the application
# To persist logs, mount a volume: docker run -v $(pwd)/logs:/app/logs -p 8000:8000 <image>
CMD ["uv", "run", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--log-config", "logging.yaml"]
