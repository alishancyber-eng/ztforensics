FROM python:3.11-slim

WORKDIR /app

COPY api_gateway/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# API code
COPY api_gateway/ .

# Shared config files required by config_manager
COPY config /app/config

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]