# api/utils/oui.py
import os, csv, re, asyncio, urllib.request
from typing import Dict, Optional

_OUI_DB: Dict[str, str] = {}
_OUI_LOADED = False
_OUI_LOCK = asyncio.Lock()

# Rutas por defecto dentro del contenedor
OUI_CSV_PATH   = os.getenv("OUI_CSV", "/app/data/oui.csv")
OUI_MANUF_PATH = os.getenv("OUI_MANUF", "/app/data/manuf")
# Si dejas OUI_URL vacío, NO intentará descargar nada
OUI_URL        = os.getenv("OUI_URL", "https://standards-oui.ieee.org/oui/oui.csv")

def _normalize_prefix(s: str) -> str:
    s = re.sub(r'[^0-9A-Fa-f]', '', s).lower()
    return s[:6]

def _load_from_csv(path: str) -> int:
    count = 0
    with open(path, newline='', encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            assignment = row.get("Assignment") or ""
            org = (row.get("Organization Name") or "").strip()
            pfx = _normalize_prefix(assignment)
            if len(pfx) == 6 and org:
                _OUI_DB[pfx] = org
                count += 1
    return count

def _load_from_manuf(path: str) -> int:
    count = 0
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                prefix = parts[0].lower().replace(":", "").replace("-", "")
                vendor = " ".join(parts[1:]).strip()
                if len(prefix) >= 6 and vendor:
                    _OUI_DB[prefix[:6]] = vendor
                    count += 1
    return count

def _download_oui_csv(url: str, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as r, open(tmp, "wb") as f:
        f.write(r.read())
    os.replace(tmp, path)

async def ensure_oui_loaded() -> None:
    global _OUI_LOADED
    if _OUI_LOADED:
        return
    async with _OUI_LOCK:
        if _OUI_LOADED:
            return

        # 1) PRIORIDAD: /app/data/manuf
        if os.path.exists(OUI_MANUF_PATH):
            try:
                n = _load_from_manuf(OUI_MANUF_PATH)
                print(f"[OUI] Cargados {n} prefijos desde {OUI_MANUF_PATH} (manuf)")
                _OUI_LOADED = True
                return
            except Exception as e:
                print(f"[OUI] Error cargando manuf: {e}")

        # 2) CSV local
        if os.path.exists(OUI_CSV_PATH):
            try:
                n = _load_from_csv(OUI_CSV_PATH)
                print(f"[OUI] Cargados {n} prefijos desde {OUI_CSV_PATH} (CSV)")
                _OUI_LOADED = True
                return
            except Exception as e:
                print(f"[OUI] Error cargando CSV: {e}")

        # 3) Descarga CSV (si OUI_URL no está vacío)
        if OUI_URL:
            try:
                _download_oui_csv(OUI_URL, OUI_CSV_PATH)
                n = _load_from_csv(OUI_CSV_PATH)
                print(f"[OUI] Descargados y cargados {n} prefijos desde {OUI_URL}")
                _OUI_LOADED = True
                return
            except Exception as e:
                print(f"[OUI] No se pudo descargar {OUI_URL}: {e}")

        print("[OUI] No hay base OUI disponible.")

def mac_to_vendor(mac: Optional[str]) -> str:
    if not mac:
        return ""
    pfx = _normalize_prefix(mac)
    if len(pfx) < 6:
        return ""
    return _OUI_DB.get(pfx[:6], "")

def oui_count() -> int:
    return len(_OUI_DB)

