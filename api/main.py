from fastapi import FastAPI
from api.routers import status, devices, scan
from api.database import init_db
from fastapi.openapi.utils import get_openapi
from api.utils.oui import ensure_oui_loaded, oui_count

app = FastAPI()

@app.on_event("startup")
async def on_startup():
    await init_db()
    # cargar OUI en memoria
    await ensure_oui_loaded()
    print(f"[OUI] Prefijos disponibles en memoria: {oui_count()}")

# Healthcheck sin versión
app.include_router(status.router)

# Rutas versionadas
app.include_router(devices.router, prefix="/v2")
app.include_router(scan.router,    prefix="/v2")

def custom_openapi():
    app.openapi_schema = None
    openapi_schema = get_openapi(
        title="ScanLin API",
        version="1.0.0",
        description="API de exploración de red ScanLin",
        routes=app.routes,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

