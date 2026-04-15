"""
hado.cybersec.vulndb — CVE/vulnerability database integration.

Fuentes:
  1. NVD (NIST National Vulnerability Database) — API v2 pública, sin auth
  2. CVE Search (cve.circl.lu) — API REST pública, sin auth
  3. Base de datos local embebida — funciona offline, CVEs críticos 2020-2024

Uso directo:
    from hado.cybersec.vulndb import search_cve, lookup_cve, search_product
"""
from __future__ import annotations

import json
import re
import time
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, List, Optional, Any


# ─── Local CVE database (embedded, offline-first) ────────────────────────────

_LOCAL_CVE_DB: List[Dict] = [
    # Log4Shell
    {
        "id": "CVE-2021-44228",
        "description": "Apache Log4j2 JNDI injection. Remote code execution via crafted log messages. CVSS 10.0 CRITICAL.",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "product": "log4j",
        "vendor": "apache",
        "cwe": "CWE-917",
        "published": "2021-12-10",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        "exploit_available": True,
        "patch": "log4j >= 2.17.0",
    },
    # Spring4Shell
    {
        "id": "CVE-2022-22965",
        "description": "Spring Framework RCE via data binding on JDK 9+. CVSS 9.8 CRITICAL.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "product": "spring-webmvc",
        "vendor": "pivotal",
        "cwe": "CWE-94",
        "published": "2022-04-01",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
        "exploit_available": True,
        "patch": "Spring Framework >= 5.3.18",
    },
    # ProxyLogon
    {
        "id": "CVE-2021-26855",
        "description": "Microsoft Exchange Server SSRF leading to RCE (ProxyLogon). CVSS 9.8 CRITICAL.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "product": "microsoft exchange server",
        "vendor": "microsoft",
        "cwe": "CWE-918",
        "published": "2021-03-02",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-26855"],
        "exploit_available": True,
        "patch": "Exchange 2013 CU23+, 2016 CU19+, 2019 CU8+",
    },
    # EternalBlue
    {
        "id": "CVE-2017-0144",
        "description": "Windows SMBv1 remote code execution (EternalBlue / WannaCry). CVSS 9.3 CRITICAL.",
        "cvss_score": 9.3,
        "severity": "CRITICAL",
        "product": "windows smb",
        "vendor": "microsoft",
        "cwe": "CWE-119",
        "published": "2017-03-14",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
        "exploit_available": True,
        "patch": "MS17-010",
    },
    # Heartbleed
    {
        "id": "CVE-2014-0160",
        "description": "OpenSSL Heartbleed: read server memory via malformed heartbeat requests. CVSS 7.5 HIGH.",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "product": "openssl",
        "vendor": "openssl",
        "cwe": "CWE-125",
        "published": "2014-04-07",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2014-0160"],
        "exploit_available": True,
        "patch": "OpenSSL >= 1.0.1g",
    },
    # Shellshock
    {
        "id": "CVE-2014-6271",
        "description": "GNU Bash arbitrary command injection via crafted environment variables (Shellshock). CVSS 10.0.",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "product": "bash",
        "vendor": "gnu",
        "cwe": "CWE-78",
        "published": "2014-09-24",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2014-6271"],
        "exploit_available": True,
        "patch": "bash >= 4.3 patch 25",
    },
    # Dirty COW
    {
        "id": "CVE-2016-5195",
        "description": "Linux kernel race condition in copy-on-write (Dirty COW). Local privilege escalation. CVSS 7.8 HIGH.",
        "cvss_score": 7.8,
        "severity": "HIGH",
        "product": "linux kernel",
        "vendor": "linux",
        "cwe": "CWE-362",
        "published": "2016-10-19",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2016-5195"],
        "exploit_available": True,
        "patch": "Linux >= 4.8.3",
    },
    # BlueKeep
    {
        "id": "CVE-2019-0708",
        "description": "Windows Remote Desktop Services RCE — no auth required (BlueKeep). CVSS 9.8 CRITICAL.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "product": "windows rdp",
        "vendor": "microsoft",
        "cwe": "CWE-416",
        "published": "2019-05-14",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
        "exploit_available": True,
        "patch": "KB4499175 (Windows 7 / Server 2008 R2)",
    },
    # PrintNightmare
    {
        "id": "CVE-2021-34527",
        "description": "Windows Print Spooler RCE (PrintNightmare). CVSS 8.8 HIGH.",
        "cvss_score": 8.8,
        "severity": "HIGH",
        "product": "windows print spooler",
        "vendor": "microsoft",
        "cwe": "CWE-269",
        "published": "2021-07-01",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-34527"],
        "exploit_available": True,
        "patch": "KB5004945",
    },
    # ProxyShell
    {
        "id": "CVE-2021-34473",
        "description": "Microsoft Exchange Server pre-auth path confusion RCE (ProxyShell). CVSS 9.8 CRITICAL.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "product": "microsoft exchange server",
        "vendor": "microsoft",
        "cwe": "CWE-22",
        "published": "2021-07-13",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-34473"],
        "exploit_available": True,
        "patch": "Exchange Cumulative Update July 2021",
    },
    # Log4j 2nd
    {
        "id": "CVE-2021-45046",
        "description": "Apache Log4j2 incomplete fix for CVE-2021-44228. Context lookup JNDI injection. CVSS 9.0 CRITICAL.",
        "cvss_score": 9.0,
        "severity": "CRITICAL",
        "product": "log4j",
        "vendor": "apache",
        "cwe": "CWE-917",
        "published": "2021-12-14",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-45046"],
        "exploit_available": True,
        "patch": "log4j >= 2.16.0",
    },
    # OpenSSH regreSSHion
    {
        "id": "CVE-2024-6387",
        "description": "OpenSSH regreSSHion: unauthenticated RCE via race condition in signal handler (glibc Linux). CVSS 8.1 HIGH.",
        "cvss_score": 8.1,
        "severity": "HIGH",
        "product": "openssh",
        "vendor": "openbsd",
        "cwe": "CWE-364",
        "published": "2024-07-01",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
        "exploit_available": False,
        "patch": "OpenSSH >= 9.8p1",
    },
    # MOVEit
    {
        "id": "CVE-2023-34362",
        "description": "MOVEit Transfer SQL injection leading to RCE. Exploited by Cl0p ransomware group. CVSS 9.8 CRITICAL.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "product": "moveit transfer",
        "vendor": "progress",
        "cwe": "CWE-89",
        "published": "2023-06-02",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-34362"],
        "exploit_available": True,
        "patch": "MOVEit Transfer >= 2023.0.1",
    },
    # Citrix Bleed
    {
        "id": "CVE-2023-4966",
        "description": "Citrix NetScaler ADC/Gateway session token leak (Citrix Bleed). CVSS 9.4 CRITICAL.",
        "cvss_score": 9.4,
        "severity": "CRITICAL",
        "product": "citrix netscaler adc",
        "vendor": "citrix",
        "cwe": "CWE-119",
        "published": "2023-10-10",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-4966"],
        "exploit_available": True,
        "patch": "NetScaler ADC >= 13.1-49.13",
    },
    # Apache Struts
    {
        "id": "CVE-2023-50164",
        "description": "Apache Struts file upload parameter manipulation RCE. CVSS 9.8 CRITICAL.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "product": "apache struts",
        "vendor": "apache",
        "cwe": "CWE-552",
        "published": "2023-12-07",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-50164"],
        "exploit_available": True,
        "patch": "Struts >= 6.3.0.2",
    },
]


# ─── CVE ID validation ────────────────────────────────────────────────────────

_CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)


def is_valid_cve_id(cve_id: str) -> bool:
    """Valida que un string sea un CVE ID válido (CVE-YYYY-NNNN)."""
    return bool(_CVE_PATTERN.match(cve_id.strip()))


# ─── Local database search ────────────────────────────────────────────────────

def search_local(query: str, min_cvss: float = 0.0) -> List[Dict]:
    """
    Busca en la base de datos local embebida.

    Args:
        query:    texto a buscar (CVE ID, producto, descripción, vendor)
        min_cvss: puntaje CVSS mínimo para filtrar

    Returns:
        Lista de CVEs encontrados
    """
    query_lower = query.lower().strip()
    results = []

    for cve in _LOCAL_CVE_DB:
        if cve.get("cvss_score", 0) < min_cvss:
            continue
        # Match en cualquier campo de texto
        searchable = ' '.join([
            cve.get("id", ""),
            cve.get("description", ""),
            cve.get("product", ""),
            cve.get("vendor", ""),
            cve.get("cwe", ""),
        ]).lower()

        if query_lower in searchable:
            results.append(cve.copy())

    return sorted(results, key=lambda x: x.get("cvss_score", 0), reverse=True)


def lookup_local(cve_id: str) -> Optional[Dict]:
    """Busca un CVE específico en la base de datos local."""
    cve_id_upper = cve_id.strip().upper()
    for cve in _LOCAL_CVE_DB:
        if cve.get("id", "").upper() == cve_id_upper:
            return cve.copy()
    return None


# ─── NVD API v2 ───────────────────────────────────────────────────────────────

_NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_SEARCH_BASE = "https://cve.circl.lu/api"


def _http_get(url: str, timeout: int = 10) -> Optional[Dict]:
    """HTTP GET con manejo de errores. Retorna JSON dict o None."""
    try:
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'hado-cybersec/0.4 (security research)',
                'Accept': 'application/json',
            }
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            return json.loads(data.decode('utf-8'))
    except urllib.error.HTTPError as e:
        return {"_error": f"HTTP {e.code}: {e.reason}", "_url": url}
    except urllib.error.URLError as e:
        return {"_error": f"Network error: {e.reason}", "_url": url}
    except Exception as e:
        return {"_error": str(e), "_url": url}


def _nvd_cve_to_dict(nvd_item: Dict) -> Dict:
    """Convierte un item de la API NVD v2 al formato estándar de hado."""
    cve_data = nvd_item.get("cve", {})
    cve_id = cve_data.get("id", "")

    # Descripción en inglés
    descriptions = cve_data.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description")

    # CVSS score (v3.1 primero, luego v3.0, luego v2)
    metrics = cve_data.get("metrics", {})
    cvss_score = 0.0
    severity = "UNKNOWN"

    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(version, [])
        if metric_list:
            metric = metric_list[0]
            cvss_data = metric.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", metric.get("baseSeverity", "UNKNOWN"))
            break

    # Referencias
    refs = [r.get("url", "") for r in cve_data.get("references", [])][:5]

    # Configuraciones (productos afectados)
    configs = cve_data.get("configurations", [])
    products = []
    for config in configs:
        for node in config.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                cpe_str = cpe.get("criteria", "")
                # Parse: cpe:2.3:a:vendor:product:version...
                parts = cpe_str.split(":")
                if len(parts) > 4:
                    products.append(f"{parts[3]}:{parts[4]}")

    return {
        "id": cve_id,
        "description": desc[:500],
        "cvss_score": cvss_score,
        "severity": severity,
        "product": products[0] if products else "unknown",
        "products": products[:5],
        "vendor": products[0].split(":")[0] if products else "unknown",
        "published": cve_data.get("published", "")[:10],
        "lastModified": cve_data.get("lastModified", "")[:10],
        "references": refs,
        "source": "nvd",
        "exploit_available": None,  # NVD free API no tiene esta info
    }


def lookup_cve(cve_id: str, use_local_fallback: bool = True) -> Optional[Dict]:
    """
    Busca un CVE específico por ID.

    Estrategia: base de datos local → NVD API → cve.circl.lu

    Args:
        cve_id:             ID del CVE (ej: 'CVE-2021-44228')
        use_local_fallback: si True, intenta local si API falla

    Returns:
        Dict con datos del CVE o None si no encontrado

    Ejemplo:
        >>> cve = lookup_cve('CVE-2021-44228')
        >>> print(cve['description'])
        Apache Log4j2 JNDI injection...
        >>> print(cve['cvss_score'])
        10.0
    """
    cve_id = cve_id.strip().upper()

    if not is_valid_cve_id(cve_id):
        raise ValueError(f"CVE ID inválido: {cve_id}. Formato: CVE-YYYY-NNNN")

    # 1. Base local (más rápida)
    local = lookup_local(cve_id)
    if local:
        return local

    # 2. NVD API v2
    url = f"{_NVD_API_BASE}?cveId={urllib.parse.quote(cve_id)}"
    result = _http_get(url)

    if result and "_error" not in result:
        vulns = result.get("vulnerabilities", [])
        if vulns:
            return _nvd_cve_to_dict(vulns[0])

    # 3. Fallback: cve.circl.lu
    url2 = f"{_CVE_SEARCH_BASE}/cve/{urllib.parse.quote(cve_id)}"
    result2 = _http_get(url2)

    if result2 and "_error" not in result2 and result2.get("id"):
        return _circl_to_dict(result2)

    return None


def _circl_to_dict(data: Dict) -> Dict:
    """Convierte respuesta de cve.circl.lu al formato estándar."""
    cvss = data.get("cvss", 0) or 0
    try:
        cvss = float(cvss)
    except (ValueError, TypeError):
        cvss = 0.0

    return {
        "id": data.get("id", ""),
        "description": data.get("summary", "")[:500],
        "cvss_score": cvss,
        "severity": _cvss_to_severity(cvss),
        "product": data.get("vulnerable_product", ["unknown"])[0] if data.get("vulnerable_product") else "unknown",
        "products": data.get("vulnerable_product", [])[:5],
        "vendor": "",
        "published": data.get("Published", "")[:10],
        "lastModified": data.get("Modified", "")[:10],
        "references": data.get("references", [])[:5],
        "source": "circl",
        "cwe": data.get("cwe", ""),
        "exploit_available": None,
    }


def _cvss_to_severity(score: float) -> str:
    """Convierte CVSS score numérico a etiqueta de severidad."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "NONE"


# ─── Product search ───────────────────────────────────────────────────────────

def search_product(
    product: str,
    vendor: str = "",
    min_cvss: float = 0.0,
    limit: int = 20,
    use_api: bool = True,
) -> List[Dict]:
    """
    Busca CVEs que afecten a un producto específico.

    Args:
        product:  nombre del producto (ej: 'apache log4j', 'openssl', 'wordpress')
        vendor:   vendor del producto (opcional)
        min_cvss: puntaje CVSS mínimo (0.0-10.0)
        limit:    máximo de resultados
        use_api:  si True, consulta NVD API (puede ser lento)

    Returns:
        Lista de CVEs ordenada por CVSS (mayor primero)

    Ejemplo:
        >>> vulns = search_product('log4j', min_cvss=7.0)
        >>> for v in vulns:
        ...     print(f"{v['id']} — CVSS {v['cvss_score']} — {v['severity']}")
    """
    results = []

    # 1. Buscar en local
    query = f"{vendor} {product}".strip()
    local_results = search_local(query, min_cvss)
    results.extend(local_results)
    seen_ids = {r["id"] for r in results}

    # 2. NVD API por keyword
    if use_api:
        keyword = f"{vendor} {product}".strip() if vendor else product
        url = (f"{_NVD_API_BASE}"
               f"?keywordSearch={urllib.parse.quote(keyword)}"
               f"&resultsPerPage={min(limit, 50)}")
        if min_cvss > 0:
            url += f"&cvssV3Severity={_cvss_to_severity(min_cvss)}"

        api_result = _http_get(url)
        if api_result and "_error" not in api_result:
            for vuln in api_result.get("vulnerabilities", []):
                parsed = _nvd_cve_to_dict(vuln)
                if parsed["id"] not in seen_ids and parsed["cvss_score"] >= min_cvss:
                    results.append(parsed)
                    seen_ids.add(parsed["id"])
                if len(results) >= limit:
                    break

    results.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
    return results[:limit]


def search_cve(
    query: str,
    min_cvss: float = 0.0,
    limit: int = 20,
    use_api: bool = True,
) -> List[Dict]:
    """
    Búsqueda general de CVEs por texto libre.

    Busca en: descripción, producto, vendor, CWE, CVE ID.

    Args:
        query:    texto libre (ej: 'buffer overflow apache', 'remote code execution ssh')
        min_cvss: filtro de puntaje mínimo
        limit:    máximo de resultados
        use_api:  consultar NVD si True

    Returns:
        Lista de CVEs relevantes, ordenada por CVSS

    Ejemplo:
        >>> results = search_cve('remote code execution windows', min_cvss=9.0)
        >>> for r in results[:3]:
        ...     print(r['id'], r['cvss_score'])
    """
    # Check if it's a direct CVE ID lookup
    if is_valid_cve_id(query.strip()):
        result = lookup_cve(query.strip(), use_local_fallback=True)
        return [result] if result else []

    results = []

    # 1. Local DB
    local = search_local(query, min_cvss)
    results.extend(local)
    seen_ids = {r["id"] for r in results}

    # 2. NVD keyword search
    if use_api:
        url = (f"{_NVD_API_BASE}"
               f"?keywordSearch={urllib.parse.quote(query)}"
               f"&resultsPerPage={min(limit, 50)}")

        api_result = _http_get(url)
        if api_result and "_error" not in api_result:
            for vuln in api_result.get("vulnerabilities", []):
                parsed = _nvd_cve_to_dict(vuln)
                if parsed["id"] not in seen_ids and parsed["cvss_score"] >= min_cvss:
                    results.append(parsed)
                    seen_ids.add(parsed["id"])
                if len(results) >= limit:
                    break

    results.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
    return results[:limit]


# ─── Recent CVEs ─────────────────────────────────────────────────────────────

def get_recent_critical(days: int = 30, limit: int = 20) -> List[Dict]:
    """
    Retorna CVEs críticos recientes desde NVD API.

    Args:
        days:  cuántos días atrás buscar (default: 30)
        limit: máximo de resultados

    Returns:
        Lista de CVEs CRITICAL con CVSS >= 9.0
    """
    from datetime import datetime, timedelta

    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)

    # Format: 2023-01-01T00:00:00.000
    start_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    end_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

    url = (f"{_NVD_API_BASE}"
           f"?cvssV3Severity=CRITICAL"
           f"&pubStartDate={urllib.parse.quote(start_str)}"
           f"&pubEndDate={urllib.parse.quote(end_str)}"
           f"&resultsPerPage={min(limit, 50)}")

    result = _http_get(url)

    if result and "_error" not in result:
        vulns = result.get("vulnerabilities", [])
        return [_nvd_cve_to_dict(v) for v in vulns[:limit]]

    # Fallback: local DB filtrado por fecha si API falla
    return [c for c in _LOCAL_CVE_DB if c.get("cvss_score", 0) >= 9.0][:limit]


# ─── Exploit check ────────────────────────────────────────────────────────────

def has_known_exploit(cve_id: str) -> Optional[bool]:
    """
    Verifica si un CVE tiene exploits públicos conocidos.
    Consulta base local primero, luego cve.circl.lu.

    Returns:
        True si hay exploit, False si no, None si desconocido
    """
    local = lookup_local(cve_id)
    if local and local.get("exploit_available") is not None:
        return local["exploit_available"]

    # cve.circl.lu incluye campo 'vulnerable_configuration' pero no exploit_available directamente
    # Revisamos si hay exploit-db reference en referencias
    cve = lookup_cve(cve_id)
    if cve:
        refs = cve.get("references", [])
        exploit_domains = ["exploit-db.com", "exploitdb.com", "packetstormsecurity.com",
                           "metasploit.com", "github.com/exploit"]
        for ref in refs:
            if any(d in ref.lower() for d in exploit_domains):
                return True
        return local["exploit_available"] if local else None

    return None


# ─── Severity analysis ────────────────────────────────────────────────────────

def analyze_cve_list(cve_ids: List[str]) -> Dict:
    """
    Analiza una lista de CVE IDs y retorna estadísticas de riesgo.

    Args:
        cve_ids: lista de CVE IDs

    Returns:
        dict con estadísticas: total, críticos, altos, medios, bajos,
        risk_score promedio, exploits_known, lista de CVEs

    Ejemplo:
        >>> result = analyze_cve_list(['CVE-2021-44228', 'CVE-2014-0160'])
        >>> print(result['risk_score'])
        8.75
    """
    cves = []
    for cve_id in cve_ids:
        cve = lookup_cve(cve_id, use_local_fallback=True)
        if cve:
            cves.append(cve)

    if not cves:
        return {
            "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
            "risk_score": 0, "exploits_known": 0, "cves": []
        }

    critical = sum(1 for c in cves if c.get("cvss_score", 0) >= 9.0)
    high = sum(1 for c in cves if 7.0 <= c.get("cvss_score", 0) < 9.0)
    medium = sum(1 for c in cves if 4.0 <= c.get("cvss_score", 0) < 7.0)
    low = sum(1 for c in cves if 0 < c.get("cvss_score", 0) < 4.0)
    exploits = sum(1 for c in cves if c.get("exploit_available") is True)
    avg_score = sum(c.get("cvss_score", 0) for c in cves) / len(cves)

    return {
        "total": len(cves),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "risk_score": round(avg_score, 2),
        "exploits_known": exploits,
        "cves": sorted(cves, key=lambda x: x.get("cvss_score", 0), reverse=True),
    }


def get_local_db_stats() -> Dict:
    """Retorna estadísticas de la base de datos local."""
    return {
        "total_cves": len(_LOCAL_CVE_DB),
        "critical": sum(1 for c in _LOCAL_CVE_DB if c.get("severity") == "CRITICAL"),
        "high": sum(1 for c in _LOCAL_CVE_DB if c.get("severity") == "HIGH"),
        "with_exploits": sum(1 for c in _LOCAL_CVE_DB if c.get("exploit_available") is True),
        "products": list({c.get("product", "unknown") for c in _LOCAL_CVE_DB}),
    }
