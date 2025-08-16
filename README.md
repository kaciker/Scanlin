# ScanLin — README

## Resumen
ScanLin: backend FastAPI para exploración y gestión de red local (gateway + Postgres + optional ui_port proxy/socat). Soporta escaneo por subred, SSE para UI, y persistencia en Postgres.

## Archivos importantes
- `/api/main.py` — arranque FastAPI. :contentReference[oaicite:3]{index=3}
- `/api/database.py` — engine asyncpg y sesión; revisar pool/timeouts. :contentReference[oaicite:4]{index=4}
- `/api/routers/scan.py` — lógica de escaneo y persistencia por IP. :contentReference[oaicite:5]{index=5}
- `/api/routers/devices.py` — endpoints CRUD de devices. :contentReference[oaicite:6]{index=6}

## Variables .env mínimas (ejemplo)
