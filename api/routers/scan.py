# api/routers/scan.py
from fastapi import APIRouter, HTTPException, Depends, Request, Query
from fastapi.responses import StreamingResponse, HTMLResponse, JSONResponse
from ipaddress import ip_network, ip_address, IPv4Address
from typing import List, Dict, Any, Optional
import asyncio, re, json, socket, ssl, subprocess, os, time
from asyncio import Semaphore, create_subprocess_exec, subprocess as asp
from sqlmodel import select
from api.models.device import Device
from api.database import get_session
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
import ping3
# OUI
from api.utils.oui import mac_to_vendor, ensure_oui_loaded

router = APIRouter(tags=["scan"]) 
semaforo = Semaphore(32)


# ---------- helpers de sistema ----------
def _has_cmd(cmd: str) -> bool:
    try:
        subprocess.check_call(["which", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


# ---------- Multiobjetivo: CIDR / IP / Rango, separados por coma/espacio/; ----------
def parse_targets(expr: str) -> List[str]:
    """Ej: "192.168.31.0/25,192.168.31.200-192.168.31.220 192.168.31.252" → [ips]
    Acepta CIDR, IP sueltas y rangos A-B. Devuelve lista única ordenada por IP.
    """
    if not expr:
        return []
    tokens = re.split(r"[,;\s]+", expr.strip())
    seen, out = set(), []
    for tok in tokens:
        if not tok:
            continue
        if "/" in tok:  # CIDR
            try:
                for ip in ip_network(tok, strict=False).hosts():
                    s = str(ip)
                    if s not in seen:
                        seen.add(s); out.append(s)
            except ValueError:
                pass
            continue
        if "-" in tok:  # rango A-B
            a, b = tok.split("-", 1)
            try:
                sa, sb = ip_address(a), ip_address(b)
                if sa.version == 4 and sb.version == 4 and int(sb) >= int(sa):
                    cur = int(sa); lim = int(sb)
                    while cur <= lim and len(out) < 1_000_000:
                        s = str(IPv4Address(cur))
                        if s not in seen:
                            seen.add(s); out.append(s)
                        cur += 1
            except ValueError:
                pass
            continue
        # IP suelta
        try:
            s = str(ip_address(tok))
            if s not in seen:
                seen.add(s); out.append(s)
        except ValueError:
            pass
    # Ordenar por IP
    def ipnum(s: str):
        p = [int(x) for x in s.split(".")]
        return (p[0]<<24) + (p[1]<<16) + (p[2]<<8) + p[3]
    out.sort(key=ipnum)
    return out


# ---------- Ping & enriquecimiento ----------
async def ping_host(ip: str) -> bool:
    """Ping con semáforo; usa ping3 (en hilo) y fallback a ping del sistema."""
    async with semaforo:
        try:
            r = await asyncio.to_thread(ping3.ping, ip, 1)  # timeout=1s
            if r is not None:
                return True
        except Exception:
            pass
        try:
            p = await create_subprocess_exec(
                "ping", "-c", "1", "-W", "1", ip,
                stdout=asp.DEVNULL, stderr=asp.DEVNULL
            )
            return (await p.wait()) == 0
        except Exception:
            return False


def get_mac_best_effort(ip: str) -> str:
    """Obtiene MAC desde ARP: ip neigh → /proc/net/arp → (opcional) arping."""
    import re as _re

    def _parse_mac(s: str) -> str:
        m = _re.search(r'(([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})', s or '')
        return m.group(1).lower() if m else ""

    # ARP activo si se habilita
    if os.getenv("ENABLE_ARPING", "0") == "1" and _has_cmd("arping"):
        iface = os.getenv("ARP_IFACE", "eth0")
        try:
            subprocess.run(
                ["arping", "-c", "1", "-w", "1", "-I", iface, ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2
            )
        except Exception:
            pass

    # 1) ip neigh
    try:
        out = subprocess.check_output(["ip", "neigh", "show", ip], text=True, timeout=1)
        mac = _parse_mac(out)
        if mac and mac != "00:00:00:00:00:00":
            return mac
    except Exception:
        pass

    # 2) /proc/net/arp
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if parts and parts[0] == ip:
                    mac = parts[3].lower()
                    if mac and mac != "00:00:00:00:00:00":
                        return mac
    except Exception:
        pass

    return ""


def resolve_dns_ptr(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def resolve_nbns(ip: str) -> str:
    if not _has_cmd("nmblookup"):
        return ""
    try:
        out = subprocess.check_output(["nmblookup", "-A", ip], text=True, timeout=1.5)
        for line in out.splitlines():
            if ("<00>" in line or "<20>" in line) and ("UNIQUE" in line or "Registered" in line):
                name = line.split()[0].strip()
                if name and name.upper() != "NAME":
                    return name
    except Exception:
        pass
    return ""


def resolve_mdns(ip: str) -> str:
    if not _has_cmd("avahi-resolve-address"):
        return ""
    try:
        out = subprocess.check_output(["avahi-resolve-address", ip], text=True, timeout=1)
        host = out.split()[0].strip()
        return host.replace(".local", "")
    except Exception:
        return ""


def _http_title_plain(ip: str, port: int) -> str:
    try:
        s = socket.create_connection((ip, port), timeout=0.8)
        req = f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode()
        s.send(req); data = s.recv(4096).decode(errors="ignore"); s.close()
        m = re.search(r"<title>(.*?)</title>", data, re.I | re.S)
        if m:
            return m.group(1).strip()[:64]
    except Exception:
        pass
    return ""


def _http_title_tls(ip: str, port: int = 443) -> str:
    try:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((ip, port), timeout=0.8)
        s = ctx.wrap_socket(raw, server_hostname=ip)
        req = f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode()
        s.send(req); data = s.recv(4096).decode(errors="ignore"); s.close()
        m = re.search(r"<title>(.*?)</title>", data, re.I | re.S)
        if m:
            return m.group(1).strip()[:64]
    except Exception:
        pass
    return ""


def resolve_http_title(ip: str) -> str:
    for port in (80, 8080):
        t = _http_title_plain(ip, port)
        if t:
            return t
    return _http_title_tls(ip, 443)


def resolve_name_best_effort(ip: str) -> Dict[str, str]:
    """
    Cadena de resolución: PTR DNS → mDNS → NBNS → HTTP title.
    Devuelve {"name": str, "source": "ptr|mdns|nbns|http|"}.
    """
    try:
        name = resolve_dns_ptr(ip)
        if name:
            return {"name": name, "source": "ptr"}
    except Exception:
        pass

    try:
        name = resolve_mdns(ip)
        if name:
            return {"name": name, "source": "mdns"}
    except Exception:
        pass

    try:
        name = resolve_nbns(ip)
        if name:
            return {"name": name, "source": "nbns"}
    except Exception:
        pass

    try:
        name = resolve_http_title(ip)
        if name:
            return {"name": name, "source": "http"}
    except Exception:
        pass

    return {"name": "", "source": ""}


async def resolve_name_best_effort_async(ip: str) -> Dict[str, str]:
    return await asyncio.to_thread(resolve_name_best_effort, ip)


# ---------- Endpoints clásicos ----------
@router.post("/scan", response_model=List[str])
async def scan_subnet(request: Request, session: AsyncSession = Depends(get_session)):
    """Escaneo clásico (ping + enrich) con persistencia. Acepta múltiples objetivos."""
    await ensure_oui_loaded()

    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Body inválido: se espera JSON")

    expr = (data or {}).get("subnet")
    tag = (data or {}).get("tag", "descubierto")
    targets = parse_targets(expr)
    if not targets:
        raise HTTPException(status_code=400, detail="Rango/Lista inválida")

    results = await asyncio.gather(*[ping_host(ip) for ip in targets])
    activos = [ip for ip, ok in zip(targets, results) if ok]

    nuevos: List[str] = []
    for ip in activos:
        name_info = await resolve_name_best_effort_async(ip)
        name = name_info.get("name", "") or f"Host {ip}"
        mac = await asyncio.to_thread(get_mac_best_effort, ip)
        vendor = mac_to_vendor(mac) if mac else ""

        q = await session.execute(select(Device).where(Device.ip == ip))
        existente = q.scalars().first()

        if existente:
            existente.last_seen = datetime.utcnow()
            if name:
                existente.name = name
            if mac:
                existente.mac = mac
            if hasattr(existente, "vendor"):
                existente.vendor = vendor
        else:
            dev = Device(name=name, ip=ip, mac=mac, os="", last_seen=datetime.utcnow(), tags=tag)
            if hasattr(dev, "vendor"):
                setattr(dev, "vendor", vendor)
            session.add(dev)
            nuevos.append(ip)

    await session.commit()
    return nuevos


# ---------- Probe helper ----------
async def tcp_connect_one(ip: str, port: int, timeout: float = 0.6) -> bool:
    def try_conn():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            s.close()
            return True
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            return False
    return await asyncio.get_event_loop().run_in_executor(None, try_conn)


async def arping_probe(ip: str, iface: Optional[str] = None, count: int = 1, timeout: int = 2) -> bool:
    if not _has_cmd("arping"):
        return False
    cmd = ["arping", "-c", str(count)]
    if iface:
        cmd += ["-I", iface]
    cmd += [ip]
    try:
        await asyncio.to_thread(subprocess.check_output, cmd, stderr=subprocess.STDOUT, timeout=timeout)
        return True
    except Exception:
        return False


async def probe_host_strict(ip: str, iface_hint: Optional[str] = None, retries: int = 2):
    """Votación ICMP/ARP/TCP para decidir alive + confidence."""
    methods = []
    votes = 0
    max_votes = 3  # icmp, arp, tcp

    # ICMP
    icmp_ok = False
    for _ in range(retries):
        try:
            ok = await ping_host(ip)
            if ok:
                icmp_ok = True
                votes += 1
                methods.append("icmp")
                break
        except Exception:
            pass

    # ARP
    arp_ok = False
    if _has_cmd("arping"):
        try:
            arp_ok = await arping_probe(ip, iface_hint, count=1)
            if arp_ok:
                votes += 1
                methods.append("arp")
        except Exception:
            pass

    # TCP
    tcp_ports = (80, 443, 22, 445, 8080)
    tcp_ok = False
    tcp_success_port = None
    for p in tcp_ports:
        ok = await tcp_connect_one(ip, p, timeout=0.5)
        if ok:
            tcp_ok = True
            tcp_success_port = p
            votes += 1
            methods.append(f"tcp/{p}")
            break

    confidence = round(votes / max_votes, 2)
    if tcp_ok or (arp_ok and icmp_ok) or confidence >= 0.6:
        alive = True
    else:
        alive = False

    return {
        "alive": alive,
        "confidence": confidence,
        "methods": methods,
        "tcp_port": tcp_success_port
    }


@router.get("/probe")
async def probe_one_ip(ip: str = Query(..., description="IP a sondear"),
                       iface: Optional[str] = Query(None, description="iface para arping (opcional)")):
    res = await probe_host_strict(ip, iface_hint=iface, retries=2)
    return JSONResponse(content={"ip": ip, **res})


# ---------- Streaming SSE ----------
@router.get("/scan/stream")
async def scan_stream(
    subnet: str,
    tag: str = "stream",
    persist: bool = Query(False, description="Si true, persiste en DB con writer por lotes"),
    session: AsyncSession = Depends(get_session)
):
    """SSE para UI; admite múltiples objetivos (CIDR/IP/rango)."""
    await ensure_oui_loaded()

    hosts = parse_targets(subnet)
    if not hosts:
        raise HTTPException(status_code=400, detail="Rango/Lista inválida")

    async def gen():
        total = len(hosts)
        yield f'event: meta\ndata: {json.dumps({"total": total, "subnet": subnet, "tag": tag})}\n\n'

        queue: Optional[asyncio.Queue] = None
        writer_task: Optional[asyncio.Task] = None
        SENTINEL = {"__done__": True}

        if persist:
            queue = asyncio.Queue()

            async def db_writer(q: asyncio.Queue, sess: AsyncSession):
                buf: List[Dict[str, Any]] = []
                BATCH = 50
                while True:
                    item = await q.get()
                    if item is None:
                        continue
                    if isinstance(item, dict) and item.get("__done__"):
                        if buf:
                            async with sess.begin():
                                for d in buf:
                                    qres = await sess.execute(select(Device).where(Device.ip == d["ip"]))
                                    existente = qres.scalars().first()
                                    if existente:
                                        existente.last_seen = datetime.utcnow()
                                        if d.get("name"):
                                            existente.name = d["name"]
                                        if d.get("mac"):
                                            existente.mac = d["mac"]
                                        if hasattr(existente, "vendor") and d.get("vendor") is not None:
                                            existente.vendor = d["vendor"]
                                    else:
                                        dev = Device(
                                            name=d.get("name") or f"Host {d['ip']}",
                                            ip=d["ip"], mac=d.get("mac", ""), os="",
                                            last_seen=datetime.utcnow(), tags=tag
                                        )
                                        if hasattr(dev, "vendor"):
                                            setattr(dev, "vendor", d.get("vendor", ""))
                                        sess.add(dev)
                            buf = []
                        break

                    buf.append(item)
                    if len(buf) >= BATCH:
                        async with sess.begin():
                            for d in buf:
                                qres = await sess.execute(select(Device).where(Device.ip == d["ip"]))
                                existente = qres.scalars().first()
                                if existente:
                                    existente.last_seen = datetime.utcnow()
                                    if d.get("name"):
                                        existente.name = d["name"]
                                    if d.get("mac"):
                                        existente.mac = d["mac"]
                                    if hasattr(existente, "vendor") and d.get("vendor") is not None:
                                        existente.vendor = d["vendor"]
                                else:
                                    dev = Device(
                                        name=d.get("name") or f"Host {d['ip']}",
                                        ip=d["ip"], mac=d.get("mac", ""), os="",
                                        last_seen=datetime.utcnow(), tags=tag
                                    )
                                    if hasattr(dev, "vendor"):
                                        setattr(dev, "vendor", d.get("vendor", ""))
                                    sess.add(dev)
                        buf = []

            writer_task = asyncio.create_task(db_writer(queue, session))

        async def worker(ip: str) -> Dict[str, Any]:
            res = await probe_host_strict(ip, iface_hint=os.getenv("ARP_IFACE", None), retries=2)
            d: Dict[str, Any] = {
                "ip": ip,
                "alive": res["alive"],
                "confidence": res["confidence"],
                "probe_methods": res["methods"]
            }
            if res.get("tcp_port"):
                d["tcp_port"] = res["tcp_port"]
            if res["alive"]:
                name_info = await resolve_name_best_effort_async(ip)
                d["name"] = name_info.get("name", "")
                d["name_source"] = name_info.get("source", "")
                d["mac"] = await asyncio.to_thread(get_mac_best_effort, ip)
                d["vendor"] = mac_to_vendor(d.get("mac", "")) if d.get("mac") else ""
            else:
                d["name"] = ""; d["name_source"] = ""; d["mac"] = ""; d["vendor"] = ""
            return d

        tasks = [asyncio.create_task(worker(ip)) for ip in hosts]
        done = 0
        for coro in asyncio.as_completed(tasks):
            try:
                d = await coro
            except Exception:
                d = {"ip": "error", "alive": False, "confidence": 0.0, "probe_methods": [], "vendor": ""}
            done += 1

            if persist and d.get("alive"):
                await queue.put(d)

            d.update({"done": done, "total": total})
            yield f"data: {json.dumps(d)}\n\n"

        if persist:
            await queue.put(SENTINEL)
            if writer_task:
                await writer_task

        yield "event: end\ndata: {}\n\n"

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


# ---------- UI (formato original + búsqueda; spinner/anillos/banners intactos) ----------
@router.get("/ui", response_class=HTMLResponse)
async def scan_ui():
    return HTMLResponse("""
<!DOCTYPE html>
<html lang=\"es\" class=\"h-full\">
<head>
  <meta charset=\"UTF-8\" />
  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
  <title>ScanLin · IP Scanner</title>
  <link rel=\"icon\" href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 96 96'%3E%3Ccircle cx='48' cy='48' r='44' fill='%230ea5e9'/%3E%3Cpath d='M48 20a28 28 0 1028 28A28.03 28.03 0 0048 20zm0 50a22 22 0 1122-22 22 22 0 01-22 22z' fill='white'/%3E%3Ccircle cx='48' cy='48' r='8' fill='white'/%3E%3C/svg%3E\" />
  <script src=\"https://cdn.tailwindcss.com\"></script>
  <meta name=\"color-scheme\" content=\"light dark\" />
  <style>
    #bar { transition: width .25s ease; }
    #spinner { width: 1.5rem; height: 1.5rem; }
    .mono { font-family: ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,\"Liberation Mono\",\"Courier New\",monospace; }
    .pill { border-radius: 9999px; padding: .125rem .5rem; font-size: .75rem; font-weight: 600; }
    .toast { animation: slideIn .25s ease; }
    @keyframes slideIn { from { transform: translateY(-6px); opacity:.0 } to { transform: translateY(0); opacity:1 } }
  </style>
</head>
<body class=\"h-full bg-slate-50 text-slate-900\">
  <div class=\"min-h-full mx-auto max-w-screen-xl p-4 sm:p-6\">
    <header class=\"flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4\">
      <div class=\"flex items-center gap-3\">
        <div class=\"size-9 rounded-xl bg-sky-500 grid place-items-center\">
          <svg viewBox=\"0 0 20 20\" class=\"size-5 text-white\" fill=\"currentColor\" aria-hidden=\"true\"><path fill-rule=\"evenodd\" d=\"M10 1.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 0 0 0-17Zm0 3a5.5 5.5 0 1 1 0 11 5.5 5.5 0 0 1 0-11Z\" clip-rule=\"evenodd\"/></svg>
        </div>
        <div>
          <h1 class=\"text-xl sm:text-2xl font-bold leading-tight\">ScanLin · IP Scanner</h1>
          <p class=\"text-sm text-slate-500\">Escaneo rápido por subred con eventos SSE en tiempo real</p>
        </div>
      </div>
      <div class=\"flex items-center gap-2\">
        <div id=\"spinner\" class=\"hidden relative\" aria-live=\"polite\" aria-label=\"Escaneando…\">
          <div id=\"spinRing\" class=\"animate-spin rounded-full border-4 border-sky-600 border-t-transparent\"></div>
        </div>
        <button id=\"btn-scan\" class=\"inline-flex items-center gap-2 bg-sky-600 hover:bg-sky-700 text-white rounded-lg px-4 py-2\">
          <svg viewBox=\"0 0 20 20\" class=\"size-4\" fill=\"currentColor\"><path d=\"M3 10a7 7 0 1 1 3.89 6.28l-2.3.77a1 1 0 0 1-1.26-1.26l.77-2.3A6.98 6.98 0 0 1 3 10Z\"/></svg>
          Escanear
        </button>
        <button id=\"btn-stop\" class=\"inline-flex items-center gap-2 bg-slate-200 hover:bg-slate-300 text-slate-900 rounded-lg px-4 py-2\">
          <svg viewBox=\"0 0 20 20\" class=\"size-4\" fill=\"currentColor\"><path d=\"M6 6h8v8H6z\"/></svg>
          Detener
        </button>
      </div>
    </header>

    <section class=\"mb-4 rounded-xl border bg-white p-3 shadow-sm\">
      <div class=\"grid grid-cols-1 md:grid-cols-5 gap-3\">
        <label class=\"block\">
          <span class=\"text-xs font-medium text-slate-600\">Subred (CIDR/IP/rango — separa con comas)</span>
          <input id=\"subnet\" type=\"text\" inputmode=\"numeric\"
                 class=\"mt-1 w-full rounded-lg border px-3 py-2 shadow-sm focus:outline-none focus:ring-2 focus:ring-sky-500\"
                 placeholder=\"192.168.31.0/24, 192.168.31.100-192.168.31.120 192.168.31.252\" value=\"192.168.31.0/24\" />
        </label>
        <label class=\"block\">
          <span class=\"text-xs font-medium text-slate-600\">Tag</span>
          <input id=\"tag\" type=\"text\"
                 class=\"mt-1 w-full rounded-lg border px-3 py-2 shadow-sm focus:outline-none focus:ring-2 focus:ring-sky-500\"
                 placeholder=\"mi-escaneo\" value=\"ui\" />
        </label>
        <div class=\"flex items-end gap-4 md:col-span-3\">
          <label class=\"inline-flex items-center gap-2\">
            <input id=\"onlyAlive\" type=\"checkbox\" class=\"size-4\" />
            <span class=\"text-sm text-slate-700\">Solo vivos</span>
          </label>
          <label class=\"inline-flex items-center gap-2\">
            <input id=\"autoResolve\" type=\"checkbox\" class=\"size-4\" checked />
            <span class=\"text-sm text-slate-700\">Auto-resolver nombres</span>
          </label>
          <div class=\"ml-auto text-sm text-slate-500\">
            <kbd class=\"px-1.5 py-0.5 rounded bg-slate-100 border\">Enter</kbd> para iniciar
          </div>
        </div>
      </div>

      <!-- Búsqueda -->
      <div class=\"mt-3\">
        <label class=\"block\">
          <span class=\"text-xs font-medium text-slate-600\">Buscar (IP / MAC / Nombre / Fabricante)</span>
          <input id=\"search\" type=\"text\"
                 class=\"mt-1 w-full rounded-lg border px-3 py-2 shadow-sm focus:outline-none focus:ring-2 focus:ring-sky-500\"
                 placeholder=\"e.g. 192.168.31.5, xiaomi, 00:1a:2b:xx:xx:xx\" />
        </label>
      </div>

      <div class=\"mt-3\">
        <div class=\"flex items-center justify-between mb-1\">
          <div class=\"text-xs text-slate-600\">Progreso</div>
          <div id=\"stats\" class=\"text-xs font-semibold text-slate-800\">0 / 0</div>
        </div>
        <div class=\"h-2 w-full overflow-hidden rounded-full bg-slate-100\">
          <div id=\"bar\" class=\"h-2 w-0 rounded-full bg-sky-500\"></div>
        </div>
        <div id=\"slowBanner\" class=\"hidden mt-2 text-xs rounded-md border border-amber-300 bg-amber-50 px-2 py-1 text-amber-800\">
          Tarda en arrancar… verificando red/DNS/DB. Mantén el navegador abierto.
        </div>
      </div>
    </section>

    <section class=\"rounded-xl border bg-white shadow-sm\">
      <div class=\"overflow-x-auto\">
        <table class=\"min-w-full text-sm\">
          <thead class=\"bg-slate-100 text-slate-700\">
            <tr>
              <th class=\"px-3 py-2 text-left\">IP</th>
              <th class=\"px-3 py-2 text-left\">Nombre</th>
              <th class=\"px-3 py-2 text-left\">MAC</th>
              <th class=\"px-3 py-2 text-left\">Fabricante</th>
              <th class=\"px-3 py-2 text-left\">Estado</th>
            </tr>
          </thead>
          <tbody id=\"tbody\" class=\"divide-y divide-slate-100\"></tbody>
        </table>
      </div>
      <div id=\"emptyState\" class=\"p-6 text-center text-slate-500 hidden\">
        Pulsa <strong>Escanear</strong> para comenzar.
      </div>
    </section>

    <div id=\"toasts\" class=\"fixed top-4 left-0 right-0 mx-auto max-w-md space-y-2 z-50 pointer-events-none\"></div>
  </div>

  <script type=\"module\">
    const $ = s => document.querySelector(s);
    const tbody = $("#tbody");
    const btnScan = $("#btn-scan");
    const btnStop = $("#btn-stop");
    const subnet = $("#subnet");
    const tag = $("#tag");
    const onlyAlive = $("#onlyAlive");
    const autoResolve = $("#autoResolve");
    const search = $("#search");

    const stats = $("#stats");
    const bar = $("#bar");
    const spinner = $("#spinner");
    const spinRing = $("#spinRing");
    const slowBanner = $("#slowBanner");
    const emptyState = $("#emptyState");
    const toasts = $("#toasts");

    let es = null; let firstPayloadAt = 0; let startAt = 0; let slowTimer = 0; let redTimer = 0; let done = 0, total = 0;

    const showToast = (text, type="error") => {
      const el = document.createElement("div");
      el.className = `toast pointer-events-auto rounded-lg border px-3 py-2 text-sm shadow ${
        type==="error" ? "bg-rose-50 border-rose-200 text-rose-800" :
        type==="warn"  ? "bg-amber-50 border-amber-200 text-amber-800" :
                          "bg-emerald-50 border-emerald-200 text-emerald-800"}`;
      el.textContent = text; toasts.appendChild(el); setTimeout(()=> el.remove(), 3500);
    };

    const ipCmp = (a, b) => { const pa=a.split(".").map(n=>+n), pb=b.split(".").map(n=>+n); for(let i=0;i<4;i++){ if(pa[i]!==pb[i]) return pa[i]-pb[i]; } return 0; };

    const model = (()=>{ const rows=new Map(); return {
      upsert(d){ if(!d||!d.ip) return; const prev=rows.get(d.ip)||{}; rows.set(d.ip,{...prev,...d}); },
      list(){ return Array.from(rows.values()).sort((a,b)=>ipCmp(a.ip,b.ip)); },
      clear(){ rows.clear(); }
    }; })();

    const render = () => {
      const q = (search?.value || "").trim().toLowerCase();
      const tokens = q ? q.split(/\s+/) : [];
      const items = model.list()
        .filter(r => !onlyAlive.checked || r.alive)
        .filter(r => {
          if (!tokens.length) return true;
          const blob = `${r.ip} ${r.name||""} ${r.mac||""} ${r.vendor||""}`.toLowerCase();
          return tokens.every(t => blob.includes(t));
        });

      emptyState.classList.toggle("hidden", items.length !== 0);
      tbody.innerHTML = items.map(r => {
        const status = r.alive ? `<span class=\"pill bg-emerald-100 text-emerald-700\">UP</span>` : `<span class=\"pill bg-slate-100 text-slate-600\">down</span>`;
        return `<tr>
          <td class=\"px-3 py-2 mono\">${r.ip ?? ""}</td>
          <td class=\"px-3 py-2\">${r.name ?? ""}</td>
          <td class=\"px-3 py-2 mono\">${r.mac ?? ""}</td>
          <td class=\"px-3 py-2\">${r.vendor ?? ""}</td>
          <td class=\"px-3 py-2\">${status}</td>
        </tr>`;
      }).join("");
    };

    const setProgress = () => { stats.textContent = `${done} / ${total}`; const pct = total ? Math.floor(done*100/total) : 0; bar.style.width = pct + "%"; };

    // Spinner estados
    const showSpinner = () => {
      spinner.classList.remove("hidden");
      spinRing.className = "animate-spin rounded-full border-4 border-sky-600 border-t-transparent";
      slowBanner.classList.add("hidden");
      clearTimeout(slowTimer); slowTimer = setTimeout(()=>{ if(!firstPayloadAt){ spinRing.className = "animate-spin rounded-full border-4 border-amber-500 border-t-transparent"; slowBanner.classList.remove("hidden"); } }, 3000);
      clearTimeout(redTimer); redTimer = setTimeout(()=>{ if(!firstPayloadAt){ spinRing.className = "animate-spin rounded-full border-4 border-rose-600 border-t-transparent"; showToast("El escaneo tarda en responder. ¿DB o DNS lentos?", "warn"); } }, 10000);
    };
    const hideSpinner = () => { spinner.classList.add("hidden"); slowBanner.classList.add("hidden"); clearTimeout(slowTimer); clearTimeout(redTimer); };

    // Auto-resolve (best-effort usando /v2/devices)
    let resolveQueue = new Set(); let resolveTimerId = 0;
    const scheduleResolve = (ip) => {
      if (!autoResolve.checked || !ip) return; resolveQueue.add(ip);
      if (!resolveTimerId) {
        resolveTimerId = setTimeout(async ()=>{
          const ips = Array.from(resolveQueue); resolveQueue.clear(); resolveTimerId = 0;
          try { const q = encodeURIComponent(ips.slice(0,10).join(" ")); const r = await fetch(`/v2/devices?search=${q}`);
            if (r.ok) { const arr = await r.json(); const byIp = new Map(arr.map(x=>[x.ip,x])); ips.forEach(ip=>{ const info=byIp.get(ip); if(info&&(info.name||info.mac||info.tags)){ model.upsert({ ip, name: info.name||"", mac: info.mac||"" }); } }); render(); }
          } catch {}
        }, 300);
      }
    };

    function stopScan(){ if(es){ try{ es.close(); }catch{} es=null; } hideSpinner(); setProgress(); }

    async function startScan(){
      stopScan(); firstPayloadAt=0; startAt=Date.now(); done=0; total=0; setProgress(); model.clear(); render(); emptyState.classList.add("hidden"); showSpinner();
      const s=subnet.value.trim(); const t=tag.value.trim()||"ui"; const url=`/v2/scan/stream?subnet=${encodeURIComponent(s)}&tag=${encodeURIComponent(t)}`;
      try{
        es = new EventSource(url);
        es.addEventListener("meta", e=>{ try{ const m=JSON.parse(e.data||"{}"); total=m.total||0; setProgress(); }catch{} });
        es.addEventListener("end", ()=>{ setProgress(); stopScan(); });
        es.onerror = ()=>{ showToast("Se perdió la conexión del stream.", "error"); stopScan(); };
        es.onmessage = (e)=>{
          if(!firstPayloadAt) firstPayloadAt=Date.now();
          try{
            const d = JSON.parse(e.data||"{}"); if(d.total) total=d.total; if(d.done) done=d.done;
            if(d.ip){ const row={ ip:d.ip, alive:!!d.alive, name:d.name||"", mac:d.mac||"", vendor:d.vendor||"" }; model.upsert(row); if(autoResolve.checked&&(!row.name||!row.mac)) scheduleResolve(row.ip); }
            setProgress(); render(); if(total && done>=total){ stopScan(); }
          }catch{}
        };
      }catch{ showToast("No se pudo iniciar el escaneo.", "error"); stopScan(); }
    }

    btnScan.addEventListener("click", startScan);
    btnStop.addEventListener("click", stopScan);
    onlyAlive.addEventListener("change", render);
    search?.addEventListener("input", render);
    document.addEventListener("keydown", (ev)=>{ if(ev.key==="Enter" && !ev.metaKey && !ev.ctrlKey && !ev.shiftKey && !ev.altKey){ startScan(); } });
    emptyState.classList.remove("hidden");
  </script>
</body>
</html>
""")
# EOF
