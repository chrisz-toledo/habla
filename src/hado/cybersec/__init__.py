"""
hado.cybersec — Módulo de ciberseguridad completo.

Re-exporta todas las funciones para uso directo en código transpilado.

Módulos disponibles:
  scanner    — Port scanning (TCP/UDP/SYN)
  recon      — Subdomain enum, DNS lookup, reverse lookup
  capture    — Packet capture / traffic analysis
  attack     — Brute force, fuzzing, credential testing
  analysis   — HTTP header analysis, scan risk assessment
  report     — Markdown/JSON report generation
  crypto     — Hashing, encoding, AES-256-GCM, RSA-2048/4096
  packets    — Raw packet crafting (SYN/UDP/ICMP), raw socket scans
  exploit    — Buffer overflow primitives (cyclic, p32, p64, flat, badchars)
  shellcode  — Shellcode catalog, XOR encoding, NOP sleds
  binary     — ELF/PE/Mach-O binary parsing, security protection detection
  rop        — ROP gadget finder, chain builder, execve/mprotect templates
  vulndb     — CVE/NVD database lookup, product search, exploit check
"""

# ─── Core modules ────────────────────────────────────────────────────────────
from .scanner import scan
from .recon import find_subdomains, dns_lookup, reverse_lookup
from .capture import capture
from .attack import attack
from .analysis import analyze, analyze_headers, analyze_scan
from .report import report

# ─── Crypto (hashing + AES + RSA) ────────────────────────────────────────────
from .crypto import (
    # Hashing
    hash_md5,
    hash_sha1,
    hash_sha256,
    hash_sha512,
    hash_bytes_sha256,
    # Encoding
    b64_encode,
    b64_decode,
    b64_encode_bytes,
    b64_decode_bytes,
    hex_encode,
    hex_decode,
    # HMAC
    hmac_sha256,
    hmac_sha512,
    hmac_verify,
    # Tokens
    generate_token,
    generate_password,
    verify_hash,
    # AES-256-GCM
    aes_generate_key,
    aes_encrypt,
    aes_decrypt,
    aes_encrypt_string,
    aes_decrypt_string,
    aes_encrypt_file,
    aes_decrypt_file,
    # RSA
    rsa_generate_keypair,
    rsa_encrypt,
    rsa_decrypt,
    rsa_sign,
    rsa_verify,
    rsa_hybrid_encrypt,
    rsa_hybrid_decrypt,
    # Availability check
    crypto_available,
)

# ─── Packet crafting ─────────────────────────────────────────────────────────
from .packets import (
    craft_tcp_packet,
    craft_udp_packet,
    craft_icmp_packet,
    syn_scan,
    udp_scan,
    icmp_ping,
    parse_tcp_flags,
)

# ─── Exploit primitives ───────────────────────────────────────────────────────
from .exploit import (
    cyclic,
    cyclic_find,
    pattern_create,
    pattern_offset,
    p8,
    p16,
    p32,
    p64,
    u32,
    u64,
    flat,
    badchars,
    npad,
    align,
    build_bof_payload,
    build_format_string,
)

# ─── Shellcode ────────────────────────────────────────────────────────────────
from .shellcode import (
    get_shellcode,
    list_shellcodes,
    shellcode_info,
    nop_sled,
    xor_encode,
    xor_decode,
    format_shellcode,
    has_null_bytes,
    find_bad_bytes,
    customize_reverse_shell,
    SHELLCODES,
)

# ─── Binary analysis ─────────────────────────────────────────────────────────
from .binary import (
    parse_binary,
    parse_elf,
    parse_pe,
    parse_macho,
    detect_protections,
)

# ─── ROP chains ───────────────────────────────────────────────────────────────
from .rop import (
    Gadget,
    RopChain,
    find_gadgets,
    find_gadgets_in_bytes,
    find_gadget_by_name,
    find_gadgets_by_name,
    find_ret_gadgets,
    find_syscall_gadgets,
    find_pivot_gadgets,
    gadgets_summary,
    build_execve_chain,
    build_mprotect_chain,
    find_bin_sh_in_binary,
    find_string_in_binary,
    GADGET_PATTERNS_X64,
    GADGET_PATTERNS_X86,
)

# ─── Vulnerability database ───────────────────────────────────────────────────
from .vulndb import (
    lookup_cve,
    search_cve,
    search_product,
    search_local,
    lookup_local,
    get_recent_critical,
    has_known_exploit,
    analyze_cve_list,
    get_local_db_stats,
    is_valid_cve_id,
)

# ─── Public API ───────────────────────────────────────────────────────────────
__all__ = [
    # Core
    "scan", "find_subdomains", "dns_lookup", "reverse_lookup",
    "capture", "attack", "analyze", "analyze_headers", "analyze_scan", "report",

    # Crypto — hashing
    "hash_md5", "hash_sha1", "hash_sha256", "hash_sha512", "hash_bytes_sha256",
    # Crypto — encoding
    "b64_encode", "b64_decode", "b64_encode_bytes", "b64_decode_bytes",
    "hex_encode", "hex_decode",
    # Crypto — HMAC
    "hmac_sha256", "hmac_sha512", "hmac_verify",
    # Crypto — tokens
    "generate_token", "generate_password", "verify_hash",
    # Crypto — AES
    "aes_generate_key", "aes_encrypt", "aes_decrypt",
    "aes_encrypt_string", "aes_decrypt_string",
    "aes_encrypt_file", "aes_decrypt_file",
    # Crypto — RSA
    "rsa_generate_keypair", "rsa_encrypt", "rsa_decrypt",
    "rsa_sign", "rsa_verify", "rsa_hybrid_encrypt", "rsa_hybrid_decrypt",
    "crypto_available",

    # Packets
    "craft_tcp_packet", "craft_udp_packet", "craft_icmp_packet",
    "syn_scan", "udp_scan", "icmp_ping", "parse_tcp_flags",

    # Exploit primitives
    "cyclic", "cyclic_find", "pattern_create", "pattern_offset",
    "p8", "p16", "p32", "p64", "u32", "u64", "flat",
    "badchars", "npad", "align", "build_bof_payload", "build_format_string",

    # Shellcode
    "get_shellcode", "list_shellcodes", "shellcode_info",
    "nop_sled", "xor_encode", "xor_decode", "format_shellcode",
    "has_null_bytes", "find_bad_bytes", "customize_reverse_shell", "SHELLCODES",

    # Binary
    "parse_binary", "parse_elf", "parse_pe", "parse_macho", "detect_protections",

    # ROP
    "Gadget", "RopChain", "find_gadgets", "find_gadgets_in_bytes",
    "find_gadget_by_name", "find_gadgets_by_name",
    "find_ret_gadgets", "find_syscall_gadgets", "find_pivot_gadgets",
    "gadgets_summary", "build_execve_chain", "build_mprotect_chain",
    "find_bin_sh_in_binary", "find_string_in_binary",
    "GADGET_PATTERNS_X64", "GADGET_PATTERNS_X86",

    # VulnDB
    "lookup_cve", "search_cve", "search_product", "search_local", "lookup_local",
    "get_recent_critical", "has_known_exploit", "analyze_cve_list",
    "get_local_db_stats", "is_valid_cve_id",
]
