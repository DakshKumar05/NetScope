FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Optional Nmap engine. Remove this layer for a smaller image; the socket
# engine works without it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-optional.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir -r requirements-optional.txt

COPY app ./app
COPY scanner_cli ./scanner_cli

RUN mkdir -p /data && useradd -m -u 10001 scanner && chown -R scanner /data /app
USER scanner

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
