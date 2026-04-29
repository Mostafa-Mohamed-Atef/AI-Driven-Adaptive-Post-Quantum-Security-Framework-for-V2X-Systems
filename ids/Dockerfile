# IDS Service Dockerfile — includes ML dependencies
FROM python:3.9-slim

WORKDIR /app

# System dependencies for ML libraries
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    gcc g++ make \
    && rm -rf /var/lib/apt/lists/*

# IDS-specific requirements
COPY ids/requirements.txt /app/ids/requirements.txt
RUN pip install --no-cache-dir -r /app/ids/requirements.txt

# Copy application code
COPY . .

EXPOSE 5010 5011

CMD ["python", "-m", "ids.ids_service"]
