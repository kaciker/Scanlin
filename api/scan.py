# api/routers/scan.py
from fastapi import APIRouter, HTTPException, Depends, Request, Query
from fastapi.responses import StreamingResponse, HTMLResponse, JSONResponse
from ipaddress import ip_network
from typing import List, Dict, Any, Optional
import asyncio, re, json, socket, ssl, subprocess, os, time
from asyncio import gather, Semaphore, create_subprocess_exec, subprocess as asp
from sqlmodel import select
from api.models.device import Device
from api.database import get_session
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
import ping3

router = APIRouter(tags=["scan"])
semaforo = Semaphore(32)


def _has_cmd(cmd: str) -> bool:
    try:
        subprocess.check_call(["which", cmd], stdout=asp.DEVNULL, stderr=asp.DEVNULL)
        return True
    except Exception:
        return False


# ---------- Ping & enriquecimiento ----------
async def ping_host(ip: str) -> bool:
    """
    Ping con semáforo para limitar concurrencia.
    Usa ping3 (en hilo) y fallback a ping del sistema.
    """
    async with semaforo:
        # 1) ping3 síncrono en hilo
        try:
            r = await asyncio.to_thread(ping3.ping, ip, 1)  # timeout=1s
            if r is not None:
                return True
        except Exception:
            pass
        # 2) Fallback: ping del sistema
        try:
            p = await create_subprocess_exec("ping", "-c", "1", "-W", "1", ip,
                                             stdout=asp.DEVNULL, stderr=asp.DEVNULL)
            return (await p.wait()) == 0
        except Exception:
            return False


def get_mac_best_effort(ip: str) -> str:
    """
    Intentos para obtener MAC desde el host:
    - ip neigh
    - /proc/net/arp
    - arping (opcional si ENABLE_ARPING=1)
    """
    import re, subprocess
    from asyncio import subprocess as asp

    def _parse_mac(s: str) -> str:
        m = re.search(r'(([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})', s or '')
        return m.group(1).lower() if m else ""

    # Opción: ARP activo, si ENABLE_ARPING está habilitado y arping existe
    if os.getenv("ENABLE_ARPING", "0") == "1" and _has_cmd("arping"):
        iface = os.getenv("ARP_IFACE", "eth0")
        try:
            subprocess.run(
                ["arping", "-c", "1", "-w", "1", "-I", iface, ip],
                stdout=asp.DEVNULL, stderr=asp.DEVNULL, timeout=2
            )
        except Exception:
            pass

    # 1) ip neigh (si hay iproute2)
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
    # nmblookup -A ip
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
    """
    Usa avahi-resolve-address si está disponible para resolver mDNS (zeroconf).
    Devuelve nombre sin .local si se encuentra, o "".
    """
    if not _has_cmd("avahi-resolve-address"):
        return ""
    try:
        out = subprocess.check_output(["avahi-resolve-address", ip], text=True, timeout=1)
        # formato: "hostname.local\t192.168.1.211\n"
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
    Cadena de resolución:
      - PTR DNS
      - mDNS (avahi)
      - NBNS (nmblookup)
      - HTTP title
    Devuelve dict: {"name": str, "source": "ptr|mdns|nbns|http|"}.
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
    """Wrapper async para resolve_name_best_effort (ejecuta en hilo)."""
    return await asyncio.to_thread(resolve_name_best_effort, ip)


# ---------- Endpoints clásicos ----------
@router.post("/scan", response_model=List[str])
async def scan_subnet(request: Request, session: AsyncSession = Depends(get_session)):
    """
    Endpoint clásico que realiza ping a la subred, resuelve nombre/mac y persiste.
    Nota: para escaneos muy grandes preferir el modo por lotes / write-queue.
    """
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Body inválido: se espera JSON")

    subnet = (data or {}).get("subnet")
    tag = (data or {}).get("tag", "descubierto")
    if not subnet:
        raise HTTPException(status_code=400, detail="Falta el campo 'subnet'")

    try:
        hosts = [str(ip) for ip in ip_network(subnet).hosts()]
    except ValueError:
        raise HTTPException(status_code=400, detail="Rango IP inválido")

    results = await gather(*[ping_host(ip) for ip in hosts])
    activos = [ip for ip, ok in zip(hosts, results) if ok]

    nuevos: List[str] = []
    for ip in activos:
        # resolve_name_best_effort_async usa to_thread internamente
        name_info = await resolve_name_best_effort_async(ip)
        name = name_info.get("name", "") or f"Host {ip}"
        mac = await asyncio.to_thread(get_mac_best_effort, ip)

        q = await session.execute(select(Device).where(Device.ip == ip))
        existente = q.scalars().first()

        if existente:
            existente.last_seen = datetime.utcnow()
            if name:
                existente.name = name
            if mac:
                existente.mac = mac
        else:
            session.add(Device(
                name=name,
                ip=ip, mac=mac, os="", last_seen=datetime.utcnow(), tags=tag
            ))
            nuevos.append(ip)

    await session.commit()
    return nuevos


# ---------- Probe helper: detección estricta para evitar falsos UP ----------
async def tcp_connect_one(ip: str, port: int, timeout: float = 0.6) -> bool:
    """
    TCP connect quick check executed on executor to avoid blocking loop.
    """
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
    """
    Strategy for robust detection:
      - Collect votes from ICMP, ARP (if available) and TCP.
      - Return a dict with alive, confidence (0..1), methods, tcp_port.
      - Decision rules: tcp_ok -> alive, arp+icmp -> alive, else confidence >= 0.6 -> alive.
    """
    methods = []
    votes = 0
    max_votes = 3  # icmp, arp, tcp

    # ICMP attempts
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

    # ARP (if available)
    arp_ok = False
    if _has_cmd("arping"):
        try:
            arp_ok = await arping_probe(ip, iface_hint, count=1)
            if arp_ok:
                votes += 1
                methods.append("arp")
        except Exception:
            pass

    # TCP quick check on common ports
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
    alive = False
    if tcp_ok:
        alive = True
    elif arp_ok and icmp_ok:
        alive = True
    elif confidence >= 0.6:
        alive = True
    else:
        alive = False

    return {
        "alive": alive,
        "confidence": confidence,
        "methods": methods,
        "tcp_port": tcp_success_port
    }


# Diagnostic HTTP endpoint: probe single IP on demand
@router.get("/probe")
async def probe_one_ip(ip: str = Query(..., description="IP a sondear"),
                       iface: Optional[str] = Query(None, description="iface para arping (opcional)")):
    res = await probe_host_strict(ip, iface_hint=iface, retries=2)
    return JSONResponse(content={"ip": ip, **res})


# ---------- Streaming SSE: red en paralelo, BD por lotes opcional ----------
@router.get("/scan/stream")
async def scan_stream(
    subnet: str,
    tag: str = "stream",
    persist: bool = Query(False, description="Si true, persiste en DB con writer por lotes"),
    session: AsyncSession = Depends(get_session)
):
    """
    SSE streaming para UI.
    - persist=False (por defecto): emite datos sin tocar BD (rápido).
    - persist=True: activa cola y writer que hace commits por lotes (reduce I/O).
    """
    try:
        hosts = [str(ip) for ip in ip_network(subnet).hosts()]
    except ValueError:
        raise HTTPException(status_code=400, detail="Rango IP inválido")

    async def gen():
        total = len(hosts)
        # evento meta inicial
        yield f'event: meta\ndata: {json.dumps({"total": total, "subnet": subnet, "tag": tag})}\n\n'

        queue: Optional[asyncio.Queue] = None
        writer_task: Optional[asyncio.Task] = None
        SENTINEL = {"__done__": True}

        # DB writer solo si persist=True
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
                                    else:
                                        sess.add(Device(
                                            name=d.get("name") or f"Host {d['ip']}",
                                            ip=d["ip"], mac=d.get("mac", ""), os="",
                                            last_seen=datetime.utcnow(), tags=tag
                                        ))
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
                                else:
                                    sess.add(Device(
                                        name=d.get("name") or f"Host {d['ip']}",
                                        ip=d["ip"], mac=d.get("mac", ""), os="",
                                        last_seen=datetime.utcnow(), tags=tag
                                    ))
                        buf = []

            writer_task = asyncio.create_task(db_writer(queue, session))

        # Worker que realiza checks por IP (usa probe_host_strict)
        async def worker(ip: str) -> Dict[str, Any]:
            # Ejecuta la estrategia estricta
            res = await probe_host_strict(ip, iface_hint=os.getenv("ARP_IFACE", None), retries=2)
            d: Dict[str, Any] = {
                "ip": ip,
                "alive": res["alive"],
                "confidence": res["confidence"],
                "probe_methods": res["methods"]
            }
            if res.get("tcp_port"):
                d["tcp_port"] = res["tcp_port"]
            # solo hacemos enriquecimiento si alive == True (reduce I/O)
            if res["alive"]:
                name_info = await resolve_name_best_effort_async(ip)
                d["name"] = name_info.get("name", "")
                d["name_source"] = name_info.get("source", "")
                d["mac"] = await asyncio.to_thread(get_mac_best_effort, ip)
            else:
                d["name"] = ""
                d["name_source"] = ""
                d["mac"] = ""
            return d

        # Lanzamos workers concurrentes (controlados por semáforo interno del ping)
        tasks = [asyncio.create_task(worker(ip)) for ip in hosts]
        done = 0

        # procesamos resultados a medida que van llegando
        for coro in asyncio.as_completed(tasks):
            try:
                d = await coro
            except Exception:
                d = {"ip": "error", "alive": False, "confidence": 0.0, "probe_methods": []}
            done += 1

            # si persistimos, encolar solo los vivos
            if persist and d.get("alive"):
                await queue.put(d)

            d.update({"done": done, "total": total})
            # emitir evento data por cada host (incluye confidence y probe_methods)
            yield f"data: {json.dumps(d)}\n\n"

        # finalizar writer si existe
        if persist:
            await queue.put(SENTINEL)
            if writer_task:
                await writer_task

        # evento end
        yield "event: end\ndata: {}\n\n"

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


# ---------- UI simple (HTML + JS) ----------
# La UI incluida aquí muestra la tabla y utiliza 'confidence' y 'probe_methods' para decidir el estado.
# Puedes reemplazar este HTML con tu versión; he incluido una UI funcional y compacta.
@router.get("/ui", response_class=HTMLResponse)
async def scan_ui():
    return HTMLResponse("""
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ScanLin — Escaneo en tiempo real</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-50 text-slate-900">
  <div class="max-w-7xl mx-auto p-6 space-y-4">
    <!-- Toolbar -->
    <div class="flex flex-col gap-3 md:flex-row md:items-end md:gap-4">
      <div class="flex-1">
        <label class="block text-sm font-medium mb-1">Subred (CIDR)</label>
        <input id="subnet" class="w-full border rounded px-3 py-2" placeholder="192.168.31.0/24" value="192.168.31.0/24"/>
      </div>
      <div>
        <label class="block text-sm font-medium mb-1">Tag</label>
        <input id="tag" class="w-40 border rounded px-3 py-2" placeholder="oficina" value="oficina"/>
      </div>
      <div class="flex items-center gap-2">
        <button id="btn-scan" class="bg-blue-600 hover:bg-blue-700 text-white rounded px-4 py-2">Escanear</button>
        <button id="btn-stop" class="bg-slate-200 hover:bg-slate-300 text-slate-900 rounded px-4 py-2">Detener</button>
      </div>
    </div>

    <!-- Filtros -->
    <div class="flex flex-col md:flex-row gap-3 md:items-center justify-between">
      <div class="flex items-center gap-3">
        <label class="inline-flex items-center gap-2 text-sm">
          <input id="only-up" type="checkbox" class="accent-blue-600">
          Mostrar solo UP
        </label>
        <label class="inline-flex items-center gap-2 text-sm">
          <input id="only-new" type="checkbox" class="accent-blue-600">
          Solo nuevos
        </label>
      </div>
      <div class="flex items-center gap-2">
        <input id="search" class="border rounded px-3 py-2 w-64" placeholder="Buscar IP / nombre / MAC"/>
        <button id="btn-export" class="border rounded px-3 py-2">Exportar CSV</button>
      </div>
    </div>

    <!-- Progreso -->
    <div>
      <div class="w-full bg-slate-200 rounded h-2 mb-2 overflow-hidden">
        <div id="bar" class="bg-blue-600 h-2" style="width:0%"></div>
      </div>
      <div id="stats" class="text-sm text-slate-600">0 / 0</div>
    </div>

    <!-- Tabla -->
    <div class="border rounded-xl bg-white overflow-auto">
      <table class="min-w-full text-sm" id="grid">
        <thead class="sticky top-0 bg-slate-100 border-b">
          <tr>
            <th class="text-left font-semibold px-3 py-2 cursor-pointer" data-sort="ip">IP</th>
            <th class="text-left font-semibold px-3 py-2 cursor-pointer" data-sort="name">Nombre</th>
            <th class="text-left font-semibold px-3 py-2 cursor-pointer" data-sort="mac">MAC</th>
            <th class="text-left font-semibold px-3 py-2 cursor-pointer" data-sort="alive">Estado</th>
            <th class="text-left font-semibold px-3 py-2 cursor-pointer" data-sort="confidence">Conf.</th>
            <th class="text-left font-semibold px-3 py-2">Acciones</th>
          </tr>
        </thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
  </div>

<script>
/* UI JS: EventSource + render throttled. Orden correcto por IP numérica incluido. */
const $ = s => document.querySelector(s);
const qsAll = (s, r=document) => Array.from(r.querySelectorAll(s));

const tbody = $("#tbody"), bar = $("#bar"), stats = $("#stats");
const btnScan = $("#btn-scan"), btnStop = $("#btn-stop");
const subnetEl = $("#subnet"), tagEl = $("#tag");
const onlyUpEl = $("#only-up"), onlyNewEl = $("#only-new"), searchEl = $("#search");
const btnExport = $("#btn-export");

let es = null;                 // EventSource actual
let total = 0, done = 0;
let sortKey = "ip", sortAsc = true;

// Datos en memoria (mapa por IP)
const rows = new Map();

// Helpers
function fmtStateWithConfidence(alive, conf) {
  if (!alive) return '<span class="inline-flex items-center gap-1 text-slate-500"><span class="inline-block w-2 h-2 rounded-full bg-slate-400"></span>down</span>';
  if (conf < 0.6) {
    return `<span class="inline-flex items-center gap-1 text-amber-700"><span class="inline-block w-2 h-2 rounded-full bg-amber-400"></span>probable</span>`;
  }
  return '<span class="inline-flex items-center gap-1 text-green-700"><span class="inline-block w-2 h-2 rounded-full bg-green-600"></span>UP</span>';
}
const linkHttp = ip => `<a class="underline hover:no-underline" href="http://${ip}" target="_blank" rel="noopener">HTTP</a>`;
const linkHttps = ip => `<a class="underline hover:no-underline" href="https://${ip}" target="_blank" rel="noopener">HTTPS</a>`;

// Convierte IPv4 a entero (0..2^32-1)
function ipToNumber(ip) {
  if (!ip) return 0;
  const parts = ip.split('.').map(p => parseInt(p, 10) || 0);
  return parts[0]*16777216 + parts[1]*65536 + parts[2]*256 + parts[3];
}

// Render
function render() {
  const q = (searchEl.value||"").trim().toLowerCase();
  const onlyUp = !!onlyUpEl.checked;
  const onlyNew = !!onlyNewEl.checked;

  let arr = Array.from(rows.values()).filter(r => {
    if (onlyUp && !r.alive) return false;
    if (onlyNew && !r.added) return false;
    if (!q) return true;
    const blob = `${r.ip} ${r.name||""} ${r.mac||""}`.toLowerCase();
    return blob.includes(q);
  });

  // Ordenado mejorado: si sortKey es "ip", usamos ipToNumber
  arr.sort((a, b) => {
    if (sortKey === "ip") {
      const va = ipToNumber(a.ip), vb = ipToNumber(b.ip);
      return sortAsc ? (va - vb) : (vb - va);
    }

    if (sortKey === "alive" || sortKey === "added") {
      const va = a[sortKey] ? 1 : 0;
      const vb = b[sortKey] ? 1 : 0;
      return sortAsc ? (va - vb) : (vb - va);
    }

    if (sortKey === "confidence") {
      const va = (a.confidence || 0), vb = (b.confidence || 0);
      return sortAsc ? (va - vb) : (vb - va);
    }

    let va = (a[sortKey] == null) ? "" : String(a[sortKey]).toLowerCase();
    let vb = (b[sortKey] == null) ? "" : String(b[sortKey]).toLowerCase();
    if (va < vb) return sortAsc ? -1 : 1;
    if (va > vb) return sortAsc ? 1 : -1;
    return 0;
  });

  const frag = document.createDocumentFragment();
  for (const r of arr) {
    let tr = r._el;
    if (!tr) {
      tr = document.createElement("tr");
      tr.className = "border-b hover:bg-slate-50";
      r._el = tr;
    }
    const nameDisplay = r.name ? `${escapeHtml(r.name)} <span class="text-xs text-slate-400">(${escapeHtml(r.name_source||"")})</span>` : "";
    tr.innerHTML = `
      <td class="px-3 py-2 font-mono">${r.ip}</td>
      <td class="px-3 py-2">${nameDisplay}</td>
      <td class="px-3 py-2 font-mono">${r.mac||""}</td>
      <td class="px-3 py-2">${fmtStateWithConfidence(!!r.alive, r.confidence || 0)}</td>
      <td class="px-3 py-2">${(r.confidence || 0).toFixed ? (r.confidence || 0).toFixed(2) : (r.confidence || 0)}</td>
      <td class="px-3 py-2 space-x-2">${linkHttp(r.ip)} ${linkHttps(r.ip)}</td>`;
    frag.appendChild(tr);
  }
  tbody.replaceChildren(frag);

  const pct = total ? Math.floor((done*100)/total) : 0;
  bar.style.width = pct + "%";
  stats.textContent = `${done} / ${total}`;
}

function escapeHtml(s){
  return (s||"").replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

function resetView(){
  rows.clear();
  done = 0; total = 0;
  tbody.innerHTML = ""; bar.style.width = "0%"; stats.textContent = "0 / 0";
}

function startScan(){
  stopScan();
  resetView();
  const subnet = subnetEl.value.trim();
  const tag = tagEl.value.trim() || "stream";
  // Por defecto persist=false para UI rápida; añade &persist=true para guardar en BD.
  const url = `/v2/scan/stream?subnet=${encodeURIComponent(subnet)}&tag=${encodeURIComponent(tag)}&persist=false`;

  es = new EventSource(url);
  es.addEventListener("meta", ev => {
    const m = JSON.parse(ev.data); total = m.total||0; render();
  });
  es.onmessage = ev => {
    const d = JSON.parse(ev.data);
    done = d.done || done; total = d.total || total;
    const item = rows.get(d.ip) || { ip: d.ip };
    Object.assign(item, d);
    // normalizar campos
    if (!item.confidence && item.confidence !== 0) item.confidence = 0;
    if (!item.probe_methods) item.probe_methods = [];
    rows.set(d.ip, item);
    scheduleRender();
  };
  es.addEventListener("end", ()=> stopScan());
}

function stopScan(){
  if (es) { es.close(); es = null; }
  scheduleRender.flush?.();
}

// Render “throttled”
let renderTimer = null;
function scheduleRender(){
  if (renderTimer) return;
  renderTimer = setTimeout(()=>{ render(); renderTimer=null; }, 50);
}
scheduleRender.flush = ()=>{ if (renderTimer){ clearTimeout(renderTimer); render(); renderTimer=null; } };

// CSV
btnExport.addEventListener("click", ()=>{
  const hdr = ["ip","name","mac","alive","confidence","probe_methods"];
  const arr = Array.from(rows.values()).map(r => hdr.map(k => (r[k] ?? "")).join(","));
  const blob = new Blob([hdr.join(",") + "\\n" + arr.join("\\n")], {type:"text/csv"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "scanlin.csv";
  a.click();
  URL.revokeObjectURL(a.href);
});

// Acciones UI
btnScan.addEventListener("click", startScan);
btnStop.addEventListener("click", stopScan);
onlyUpEl.addEventListener("change", ()=>scheduleRender());
onlyNewEl.addEventListener("change", ()=>scheduleRender());
searchEl.addEventListener("input", ()=>scheduleRender());

// Orden por cabecera
qsAll("th[data-sort]").forEach(th=>{
  th.addEventListener("click", ()=>{
    const key = th.dataset.sort;
    if (sortKey === key) sortAsc = !sortAsc; else { sortKey = key; sortAsc = true; }
    render();
  });
});

// No escanear automáticamente al cargar
</script>
</body>
</html>
""")


# EOF
