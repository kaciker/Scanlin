# ScanLin — Final Summary (what we shipped)

This section summarizes the work completed so you can paste it at the end of your GitHub README.

---

## What’s new

* **Vendor (OUI) lookup** end‑to‑end (scanner → API → DB → UI column "Fabricante").
* **Local/Offline OUI database** support with graceful fallback.
* **Multi‑target scanning**: the subnet input now accepts **CIDR, single IPs, and ranges** (e.g., `192.168.31.0/24, 192.168.31.200-192.168.31.220 192.168.31.252`).
* **Search box** (live filter) across **IP / MAC / Name / Vendor**.
* **SSE UI polish**: spinner + slow‑start banner + progress stats.
* **Probe API** (`/v2/probe`) for quick host diagnosis (alive, methods, confidence).

---

## OUI (Vendor) lookup

### Data sources

* **Preferred (offline / reliable):** Wireshark `manuf` file.
* **Optional (online):** IEEE `oui.csv` (can rate‑limit; we disable by default).

### File locations & env vars

* Mount a writable volume and place your OUI file there:

```yaml
# docker-compose.yml
services:
  gateway:
    volumes:
      - ./data:/app/data
    environment:
      OUI_MANUF: "/app/data/manuf"   # path to wireshark manuf
      OUI_URL: ""                     # keep empty to avoid IEEE download
```

Download & seed (host):

```bash
curl -o data/manuf \
  https://raw.githubusercontent.com/wireshark/wireshark/release-4.0/manuf
```

Logs on startup should show something like:

```
[OUI] Loaded 52k prefixes from /app/data/manuf (manuf)
```

### Library entry points

* `api/utils/oui.py` — `ensure_oui_loaded()` and `mac_to_vendor(mac)`.
* Scanner uses it for each MAC; UI displays the result in the **Fabricante** column.

---

## Database change (Device.vendor)

Add a `vendor TEXT` column once (safe if repeated):

```bash
docker exec -it scanlin-postgres \
  psql -U scanlin -d scanlindb \
  -c "ALTER TABLE device ADD COLUMN IF NOT EXISTS vendor TEXT;"
```

Quick check:

```bash
docker exec -it scanlin-postgres \
  psql -U scanlin -d scanlindb \
  -c "SELECT ip, mac, vendor, name, last_seen FROM device ORDER BY ip LIMIT 20;"
```

ORM notes:

* The API updates `vendor` on upsert if the model attribute exists; otherwise it’s ignored (backward compatible).

---

## Multi‑target scanning

The subnet field accepts:

* **CIDR:** `192.168.31.0/24`
* **IP range:** `192.168.31.200-192.168.31.220`
* **Single IPs:** `192.168.31.252`
* Any combination separated by **space/comma/semicolon**.

Internally this is handled by `parse_targets()`; SSE stream and classic `/v2/scan` both use it.

---

## UI changes

* New **Search** input (live filter) matching **IP / MAC / Name / Vendor**.
* **Only alive** toggle and **Auto‑resolve names** toggle.
* Spinner (blue → amber → red) + **slow‑start banner** when DNS/DB are slow on cold start.
* Progress bar and `X / Y` stats while SSE delivers results.

---

## Name resolution notes

Name is best‑effort via the following chain:

1. **DNS PTR** (reverse lookup)
2. **mDNS** (`avahi-resolve-address` if installed in the container)
3. **NBNS/NetBIOS** (`nmblookup` if installed)
4. **HTTP/HTTPS** page `<title>` (ports 80/8080/443)

If a device has no PTR and no mDNS/NBNS, and port 80/443 does not expose a page with `<title>`, the name will be empty. This is expected behavior.

**OpenWrt tip:** Some builds redirect `http://<ip>/` to `:8080`. Either allow 8080 from LAN or configure `uhttpd` to listen on port 80 to let the title resolver work. Publishing PTR records in your LAN DNS is the cleanest fix.

---

## Useful cURL commands

Start a live scan (SSE) and persist results:

```bash
curl -N "http://<GATEWAY_IP>:8000/v2/scan/stream?subnet=192.168.31.0/24&tag=ui&persist=true" | head -n 30
```

Quick probe of one IP:

```bash
curl -s "http://<GATEWAY_IP>:8000/v2/probe?ip=192.168.31.7" | python3 -m json.tool
```

Verify OUI file inside container:

```bash
docker exec -it scanlin-gateway-1 ls -lh /app/data/manuf
```

Troubleshoot names from the container:

```bash
docker exec -it scanlin-gateway-1 sh -lc '
 ip=192.168.31.7;
 echo "PTR:"; dig +short -x $ip || true; echo;
 echo "HTTP title:"; curl -m 3 -ksS http://$ip/ | tr -d "\n\r" | sed -n "s:.*<title>\(.*\)</title>.*:\1:p" || true;
'
```

(Optional) enable mDNS/NBNS tools for diagnostics in the container:

```bash
# one-off (non persistent)
docker exec -u root -it scanlin-gateway-1 sh -lc '
  set -eux; apt-get update;
  apt-get install -y --no-install-recommends avahi-utils samba-common-bin;
'
```

---

## Docker & networking

* For **macvlan deployments**, no ports are published; give the container a LAN IP and access the API via that address.
* For **bridge deployments**, expose `8000:8000` as needed.
* Always mount `./data` → `/app/data` so the OUI database persists across rebuilds.

---

## Known limitations

* Manufacturer lookup is prefix‑based and best‑effort; randomized MACs (phones/IoT in privacy mode) won’t map.
* Names depend on DNS/mDNS/NBNS/HTTP; if none provide a value, the UI will show an empty name.
* Multi‑target scans can be heavy on very wide ranges; use reasonable concurrency.

---

## Quick checklist

* [ ] `ALTER TABLE device ADD COLUMN IF NOT EXISTS vendor TEXT;`
* [ ] `data/manuf` present and `OUI_MANUF` set to `/app/data/manuf`.
* [ ] UI shows **Fabricante** column and live **Search** input.
* [ ] Logs show OUI prefixes loaded on startup.
* [ ] `/v2/probe?ip=…` returns JSON.
* [ ] SSE `/v2/scan/stream` streams results and progress.
