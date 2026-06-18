# PolicyInsight backend — FastAPI on Python 3.12 (Linux).
FROM python:3.12-slim

# System libraries required at runtime by WeasyPrint (PDF reports).
# Per the official WeasyPrint docs for Debian >= 11 (this base image is Debian
# 12 "bookworm") using pre-built wheels, the required libraries are:
#   libpango-1.0-0  libpangoft2-1.0-0  libharfbuzz-subset0
# (WeasyPrint 60+ no longer depends on Cairo/GDK-Pixbuf.)
# fonts-dejavu-core gives the renderer at least one usable font family;
# shared-mime-info helps image type detection. The psycopg2-binary driver
# ships as a self-contained wheel and needs no extra system libs.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz-subset0 \
        shared-mime-info \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Persisted upload directory (mounted as a volume in compose).
RUN mkdir -p /app/uploads
ENV UPLOAD_DIR=/app/uploads

EXPOSE 8000

# No --reload in container; suppress the uvicorn Server header.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
