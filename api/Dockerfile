# Dockerfile
FROM python:3.11-slim

# -------- Entorno base --------
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8000 \
    UVICORN_WORKERS=1 \
    UVICORN_LOG=info

# Herramientas opcionales de debug en build: --build-arg DEBUG_TOOLS=1
ARG DEBUG_TOOLS=0

# Paquetes del sistema (mínimos) + opcionales de debug
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      iproute2 iputils-ping iputils-arping dnsutils net-tools curl libpq5 ca-certificates; \
    if [ "$DEBUG_TOOLS" = "1" ]; then \
      apt-get install -y --no-install-recommends tcpdump procps socat; \
    fi; \
    rm -rf /var/lib/apt/lists/*

# -------- App Python --------
WORKDIR /app

# Congela capa de deps
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip wheel \
 && pip install --no-cache-dir -r /app/requirements.txt

# Copiamos el proyecto completo (api/, etc.)
COPY . /app

# Usuario no-root
RUN addgroup --system app && adduser --system --ingroup app app
USER app

EXPOSE 8000

# Healthcheck a la API
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:${UVICORN_PORT}/status || exit 1

# Arranque: uvicorn parametrizable por envs
CMD ["sh","-c","exec uvicorn api.main:app --host ${UVICORN_HOST} --port ${UVICORN_PORT} --proxy-headers --log-level ${UVICORN_LOG} --timeout-keep-alive 75"]
