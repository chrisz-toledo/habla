"""
Hado cybersec — Captura de trafico de red.

Cadena de fallback (3 niveles):
  1. scapy       — maximo detalle (requiere pip install scapy)
  2. tcpdump     — bueno en Linux/Mac (requiere binario en PATH)
  3. raw sockets — funciona en cualquier Python con permisos root
                   (o en modo simulacion sin root)

Si ninguno funciona, retorna [] con un warning claro.
"""

import socket
import struct
import subprocess
import time
import warnings
from typing import List, Optional


def capture(interface: str = "any", filter_expr: str = "",
            count: int = 100, timeout: int = 10) -> List[dict]:
    """
    Captura paquetes en una interfaz de red.

    Args:
        interface: nombre de la interfaz (ej: "eth0", "en0", "any")
        filter_expr: filtro BPF (ej: "tcp port 80")
        count: numero maximo de paquetes a capturar
        timeout: tiempo maximo de captura en segundos

    Returns:
        Lista de dicts con claves: src_ip, dst_ip, protocol, port,
        payload_preview, length, timestamp.
        Retorna [] si no hay método de captura disponible.
    """
    # Nivel 1: scapy (maximo detalle)
    try:
        return _capture_scapy(interface, filter_expr, count, timeout)
    except ImportError:
        pass
    except Exception as e:
        warnings.warn(f"scapy fallo ({e}), intentando tcpdump...", RuntimeWarning, stacklevel=2)

    # Nivel 2: tcpdump (bueno en Linux/Mac)
    try:
        return _capture_tcpdump(interface, filter_expr, count, timeout)
    except FileNotFoundError:
        pass
    except Exception as e:
        warnings.warn(f"tcpdump fallo ({e}), intentando raw sockets...", RuntimeWarning, stacklevel=2)

    # Nivel 3: raw sockets (Python puro, requiere root)
    try:
        return _capture_raw_socket(interface, count, timeout)
    except PermissionError:
        warnings.warn(
            "Captura con raw sockets requiere permisos root (sudo).\n"
            "Alternativas: pip install scapy | brew install tcpdump",
            RuntimeWarning,
            stacklevel=2,
        )
    except Exception as e:
        warnings.warn(
            f"Captura de paquetes no disponible ({e}).\n"
            "Instala scapy (pip install scapy) o tcpdump para captura real.",
            RuntimeWarning,
            stacklevel=2,
        )

    return []


# ─── Nivel 1: scapy ─────────────────────────────────────────────────────────

def _capture_scapy(interface: str, filter_expr: str, count: int,
                   timeout: int) -> List[dict]:
    from scapy.all import sniff, IP, TCP, UDP  # type: ignore

    packets = sniff(
        iface=interface if interface != "any" else None,
        filter=filter_expr or None,
        count=count,
        timeout=timeout,
    )
    results = []
    for pkt in packets:
        entry = {
            "src_ip": "",
            "dst_ip": "",
            "protocol": "unknown",
            "port": 0,
            "payload_preview": "",
            "length": len(pkt),
            "timestamp": float(pkt.time),
            "summary": pkt.summary(),
        }
        if IP in pkt:
            entry["src_ip"] = pkt[IP].src
            entry["dst_ip"] = pkt[IP].dst
            entry["protocol"] = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "IP")
        if TCP in pkt:
            entry["port"] = pkt[TCP].dport
        elif UDP in pkt:
            entry["port"] = pkt[UDP].dport
        if hasattr(pkt, "load"):
            raw = bytes(pkt.load)
            entry["payload_preview"] = raw[:64].hex()
        results.append(entry)
    return results


# ─── Nivel 2: tcpdump ────────────────────────────────────────────────────────

def _capture_tcpdump(interface: str, filter_expr: str, count: int,
                     timeout: int) -> List[dict]:
    cmd = [
        "tcpdump",
        "-i", interface,
        "-c", str(count),
        "-l", "-nn",          # no DNS lookup, linea por linea
        "-tttt",              # timestamp completo
        "--immediate-mode",   # flush inmediato
    ]
    if filter_expr:
        cmd.extend(filter_expr.split())

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout + 5,  # margen extra para cierre limpio
    )

    results = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        entry = _parse_tcpdump_line(line)
        if entry:
            results.append(entry)
    return results


def _parse_tcpdump_line(line: str) -> Optional[dict]:
    """
    Parsea una linea de tcpdump -nn -tttt en un dict estructurado.

    Ejemplo de linea:
        2026-04-21 16:30:45.123456 IP 192.168.1.5.443 > 10.0.0.1.54321: ...
    """
    entry = {
        "src_ip": "",
        "dst_ip": "",
        "protocol": "unknown",
        "port": 0,
        "payload_preview": "",
        "length": 0,
        "timestamp": time.time(),
        "summary": line,
    }

    parts = line.split()
    if len(parts) < 5:
        return entry

    # Detectar protocolo
    for p in parts:
        if p in ("IP", "IP6", "ARP"):
            entry["protocol"] = p
            break

    # Buscar patron: src > dst:
    for i, part in enumerate(parts):
        if part == ">" and i > 0 and i + 1 < len(parts):
            src_raw = parts[i - 1]
            dst_raw = parts[i + 1].rstrip(":")

            # Extraer IP y puerto de formato 192.168.1.5.443
            src_ip, src_port = _split_tcpdump_addr(src_raw)
            dst_ip, dst_port = _split_tcpdump_addr(dst_raw)

            entry["src_ip"] = src_ip
            entry["dst_ip"] = dst_ip
            entry["port"] = dst_port
            break

    # Buscar length en la linea
    for part in parts:
        if part.startswith("length"):
            idx = parts.index(part)
            if idx + 1 < len(parts):
                try:
                    entry["length"] = int(parts[idx + 1])
                except ValueError:
                    pass
            break

    return entry


def _split_tcpdump_addr(addr: str) -> tuple:
    """Separa '192.168.1.5.443' en ('192.168.1.5', 443)."""
    parts = addr.split(".")
    if len(parts) >= 5:
        # IPv4: ultimas 4 partes son la IP, la ultima es el puerto
        ip = ".".join(parts[:-1])
        try:
            port = int(parts[-1])
        except ValueError:
            port = 0
        # Validar que las primeras 4 son octetos
        ip_parts = ip.split(".")
        if len(ip_parts) == 4:
            return ip, port
    return addr, 0


# ─── Nivel 3: raw sockets (Python puro) ──────────────────────────────────────

def _capture_raw_socket(interface: str, count: int, timeout: int) -> List[dict]:
    """
    Captura basica con raw sockets. Requiere root/admin.
    Solo captura paquetes IP (no filtra por BPF).
    """
    import platform

    # En macOS y Windows, raw sockets son limitados.
    # En Linux podemos usar AF_PACKET.
    system = platform.system()

    if system == "Linux":
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    else:
        # macOS/BSD: AF_INET raw socket (solo IP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    sock.settimeout(timeout)
    results = []

    try:
        start = time.time()
        while len(results) < count and (time.time() - start) < timeout:
            try:
                raw_data, addr = sock.recvfrom(65535)
                entry = _parse_raw_packet(raw_data, system)
                entry["timestamp"] = time.time()
                results.append(entry)
            except socket.timeout:
                break
            except OSError:
                break
    finally:
        sock.close()

    return results


def _parse_raw_packet(data: bytes, system: str) -> dict:
    """Parsea un paquete IP raw en un dict estructurado."""
    entry = {
        "src_ip": "",
        "dst_ip": "",
        "protocol": "unknown",
        "port": 0,
        "payload_preview": data[:64].hex() if data else "",
        "length": len(data),
        "timestamp": 0.0,
        "summary": "",
    }

    offset = 0
    if system == "Linux":
        # AF_PACKET incluye el header Ethernet (14 bytes)
        if len(data) < 14 + 20:
            return entry
        offset = 14

    if len(data) < offset + 20:
        return entry

    # IP header
    iph = data[offset:offset + 20]
    version_ihl = iph[0]
    ihl = (version_ihl & 0x0F) * 4
    protocol = iph[9]
    src_ip = socket.inet_ntoa(iph[12:16])
    dst_ip = socket.inet_ntoa(iph[16:20])

    entry["src_ip"] = src_ip
    entry["dst_ip"] = dst_ip

    proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
    entry["protocol"] = proto_map.get(protocol, f"proto({protocol})")

    # Extraer puerto destino si es TCP o UDP
    transport_offset = offset + ihl
    if protocol in (6, 17) and len(data) >= transport_offset + 4:
        src_port = struct.unpack("!H", data[transport_offset:transport_offset + 2])[0]
        dst_port = struct.unpack("!H", data[transport_offset + 2:transport_offset + 4])[0]
        entry["port"] = dst_port

    entry["summary"] = f"{src_ip}:{entry.get('port', 0)} → {dst_ip} [{entry['protocol']}]"

    return entry
