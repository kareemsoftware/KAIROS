# Base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements first
COPY ./requirements.txt /app/requirements.txt

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY ./app /app

# Expose port and command
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
