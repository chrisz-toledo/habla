"""
Habla cybersec — Reconocimiento y OSINT.
Busqueda de subdominios via DNS resolution.
"""

import socket
from typing import List, Optional


DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "api", "dev", "staging", "admin", "test",
    "smtp", "pop", "imap", "vpn", "ssh", "git", "cdn", "static",
    "assets", "beta", "alpha", "demo", "app", "portal", "secure",
    "login", "auth", "blog", "shop", "store", "media", "images",
]


def find_subdomains(domain: str, wordlist: Optional[List[str]] = None) -> List[str]:
    """
    Enumera subdominios de un dominio via DNS resolution.

    Args:
        domain: dominio objetivo (ej: "ejemplo.com")
        wordlist: lista de prefijos a probar; usa DEFAULT_WORDLIST si es None

    Returns:
        Lista de FQDNs que resuelven (estan vivos)
    """
    prefixes = wordlist if wordlist is not None else DEFAULT_WORDLIST
    alive = []

    for prefix in prefixes:
        fqdn = f"{prefix}.{domain}"
        if _resolves(fqdn):
            alive.append(fqdn)

    return alive


def _resolves(fqdn: str) -> bool:
    try:
        socket.gethostbyname(fqdn)
        return True
    except (socket.gaierror, socket.herror, OSError):
        return False


def dns_lookup(domain: str) -> dict:
    """Resolucion DNS basica de un dominio."""
    result = {"domain": domain, "ips": [], "error": None}
    try:
        infos = socket.getaddrinfo(domain, None)
        ips = list({info[4][0] for info in infos})
        result["ips"] = ips
    except socket.gaierror as e:
        result["error"] = str(e)
    return result


def reverse_lookup(ip: str) -> Optional[str]:
    """Lookup DNS inverso."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None
