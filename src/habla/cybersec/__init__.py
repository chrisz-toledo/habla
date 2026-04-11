"""
Habla cybersec — Modulo de ciberseguridad.
Re-exporta todas las funciones para uso directo en codigo transpilado.
"""

from .scanner import scan
from .recon import find_subdomains, dns_lookup, reverse_lookup
from .capture import capture
from .attack import attack
from .analysis import analyze, analyze_headers, analyze_scan
from .report import report

__all__ = [
    "scan",
    "find_subdomains",
    "dns_lookup",
    "reverse_lookup",
    "capture",
    "attack",
    "analyze",
    "analyze_headers",
    "analyze_scan",
    "report",
]
