# Dockerfile (recomendado para tu estructura actual)
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    API_PORT=8000

WORKDIR /app

# Copiamos requirements desde la raíz del build context
COPY requirements.txt /app/requirements.txt

# Herramientas útiles para debugging en contenedor
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    iproute2 iputils-ping net-tools socat gcc libpq-dev arping \
    avahi-utils samba-common-bin curl \
 && rm -rf /var/lib/apt/lists/*


# Instalar dependencias Python
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copiamos todo el proyecto en /app
COPY . /app

# Exponer puerto (interno del contenedor)
EXPOSE 8000

# Comando de arranque
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
