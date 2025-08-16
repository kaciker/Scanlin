# ScanLin — README

## Resumen
ScanLin: backend FastAPI para exploración y gestión de red local (gateway + Postgres + optional ui_port proxy/socat). Soporta escaneo por subred, SSE para UI, y persistencia en Postgres.

## Archivos importantes
- `/api/main.py` — arranque FastAPI. :contentReference[oaicite:3]{index=3}
- `/api/database.py` — engine asyncpg y sesión; revisar pool/timeouts. :contentReference[oaicite:4]{index=4}
- `/api/routers/scan.py` — lógica de escaneo y persistencia por IP. :contentReference[oaicite:5]{index=5}
- `/api/routers/devices.py` — endpoints CRUD de devices. :contentReference[oaicite:6]{index=6}

## Variables .env mínimas (ejemplo)
POSTGRES_USER=scanlin
POSTGRES_PASSWORD=clave_segura
POSTGRES_DB=scanlindb
DB_HOST=postgres
DB_PORT=5432
API_PORT=8000


## Crear red macvlan (si necesitas que el contenedor tenga visibilidad L2)

docker network create -d macvlan
--subnet=192.168.31.0/24
--gateway=192.168.31.254
-o parent=eth0
scanlin_macvlan

> Si no puedes crear macvlan por permisos/IT, usa `bridge` para pruebas.

## Despliegue local (ejemplo)
1. `docker compose up -d --build`
2. `curl http://localhost:8020/status`  (ajusta host/puerto según proxy ui_port). :contentReference[oaicite:7]{index=7}

## Troubleshooting (prioridad alta)
- `asyncpg TimeoutError` → aumentar pool size en `database.py`, revisar commits frecuentes y considerer write-queue por lotes.
- Latencia SSE al arrancar en /24 → causa habitual: muchas operaciones DB síncronas por host; activar `UI-only` para escaneos grandes. :contentReference[oaicite:8]{index=8}

## Recomendaciones rápidas
1. Implementar endpoint `scan/ui` que no use BD (UI-only) para pruebas interactivas. (Incluyo snippet más abajo.)
2. Implementar write-queue asíncrona que consuma resultados y haga commit por batch (ej. 50 items o cada 3s).
3. Ajustar pool asyncpg (min/max), timeouts y `pool_pre_ping` en `database.py`. :contentReference[oaicite:9]{index=9}

(…README continúa con pasos de CI, tests y más…)



