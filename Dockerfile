FROM python:3.11-slim

# Prevent Python from writing .pyc and buffer stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV BASEERA_CLOUD_MODE=1
ENV PORT=7860

WORKDIR /app

# Install system dependencies (libgomp1 for LightGBM)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Install PyTorch CPU first (saves ~5.5GB of GPU/CUDA packages!)
RUN pip install --no-cache-dir torch>=2.2.0 --index-url https://download.pytorch.org/whl/cpu

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create reports and uploads directory with proper permissions
RUN mkdir -p reports uploads && chmod -R 777 reports uploads

# Expose default Hugging Face Spaces port
EXPOSE 7860

# Run FastAPI app
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "7860"]
