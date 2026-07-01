FROM python:3.12-alpine

LABEL maintainer="overboardkiller" \
      org.opencontainers.image.title="Media Watchdog" \
      org.opencontainers.image.description="Cross-reference Overseerr requests with Emby watch history" \
      org.opencontainers.image.source="https://github.com/overboardkiller/media-watchdog" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY static/ ./static/

EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "120", "app:app"]
