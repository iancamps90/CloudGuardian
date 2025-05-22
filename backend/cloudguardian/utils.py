# backend/cloudguardian/utils.py

from __future__ import annotations
import json, os, re, logging, requests

from django.conf import settings
import ipaddress
from typing import Any, Dict, List, Tuple



logger = logging.getLogger(__name__)


# --- Excepciones Personalizadas ---
class CaddyAPIError(Exception):
    """Excepción base para errores relacionados con la API de administración de Caddy."""
    pass

# --- NUEVAS FUNCIONES DE CONTEO PARA HOME_VIEW ---

def get_user_caddy_routes(user_json_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extrae las rutas de Caddy de la configuración JSON de un usuario."""
    # Asegúrate de que settings.SERVIDOR_CADDY esté correctamente definido
    return user_json_data \
        .get("apps", {}) \
        .get("http", {}) \
        .get("servers", {}) \
        .get(settings.SERVIDOR_CADDY, {}) \
        .get("routes", [])

def count_ip_blocks(user_json_data: Dict[str, Any]) -> int:
    """Cuenta las rutas de bloqueo de IP en la configuración de un usuario."""
    count = 0
    routes = get_user_caddy_routes(user_json_data)
    for route in routes:
        matchers = route.get("match", [])
        handle = route.get("handle", [])
        # Un bloqueo de IP típicamente tiene un matcher 'remote_ip' y un handler 'static_response' con status 403
        if any("remote_ip" in m for m in matchers) and \
            any(h.get("handler") == "static_response" and h.get("status_code") == 403 for h in handle):
            count += 1
    return count

def count_external_destinations(user_json_data: Dict[str, Any]) -> int:
    """Cuenta los destinos externos (reverse proxy) en la configuración de un usuario."""
    count = 0
    routes = get_user_caddy_routes(user_json_data)
    for route in routes:
        handle = route.get("handle", [])
        # Un destino externo es un reverse_proxy
        if any(h.get("handler") == "reverse_proxy" and h.get("upstreams") for h in handle):
            count += 1
    return count

def count_domain_proxies(user_json_data: Dict[str, Any]) -> int:
    """Cuenta los dominios proxy (reverse proxy con matcher de host) en la configuración de un usuario."""
    count = 0
    routes = get_user_caddy_routes(user_json_data)
    for route in routes:
        matchers = route.get("match", [])
        handle = route.get("handle", [])
        is_reverse_proxy = any(h.get("handler") == "reverse_proxy" for h in handle)
        # Si es un reverse proxy y tiene un matcher de 'host' (es decir, un dominio específico)
        if is_reverse_proxy and any("host" in m for m in matchers):
            count += 1
    return count

def count_user_specific_paths(user_json_data: Dict[str, Any], username: str) -> int:
    """Cuenta las rutas con paths específicos de usuario (ej. /<username>/...)."""
    count = 0
    routes = get_user_caddy_routes(user_json_data)
    for route in routes:
        matchers = route.get("match", [])
        for matcher_group in matchers:
            paths = matcher_group.get("path", [])
            if any(p.startswith(f"/{username}/") for p in paths):
                count += 1
                break # Solo contamos una vez por ruta si ya encontramos un path de usuario
    return count

# --- Funciones de Utilidad ---
#  VALIDACIÓN DE HOST + PUERTO  (se usa en destinos_externos)

_IP_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"            # IPv4 1.2.3.4
    r"|"
    r"^\[[0-9a-fA-F:]+\]$"                  # IPv6 [2001:db8::1]
)

PUERTOS_PERMITIDOS = {80, 443}  




def dial_permitido(host: str, puerto: int) -> bool:
    """
    Devuelve True si <host>:<puerto> es seguro para hacer reverse-proxy.

    – Solo permite 80 y 443 (cambia la constante si lo necesitas).  
    – Bloquea loopback, private IPs y «localhost».
    """
    if puerto not in PUERTOS_PERMITIDOS:
        return False

    host = host.lower().strip("[]")      # quita corchetes IPv6
    if (host == "localhost"
        or host.startswith("127.")
        or host.strip("[]") == "0:0:0:0:0:0:0:1"):
        return False

    # dominio público o IP pública básica
    return bool(_IP_RE.match(host) or "." in host)


def _is_valid_domain(domain_str: str) -> bool:
    """
    Valida si una cadena es un formato de dominio válido.
    Permite subdominios y dominios de alto nivel.
    """
    # Regex para validar nombres de dominio (ej: example.com, sub.example.com, example.co.uk)
    # No es exhaustiva para todos los TLDs, pero cubre la mayoría de casos comunes.
    return bool(re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$", domain_str))


# VALIDACIÓN DE URL DE DESTINO 
def _is_valid_target_url(url: str) -> bool:
    """
    Valida si una cadena es una URL de destino válida para Caddy.
    Acepta IPs (IPv4/v6), nombres de host o URLs completas (http/https/ftp).
    """
    # Patrón para IPs (v4/v6), localhost o nombres de dominio con puerto opcional
    ip_host_pattern = r"^(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|\[(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\]|(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}|localhost)(?::\d{1,5})?$"
    
    # Patrón para URLs completas con esquema (http/https/ftp)
    url_pattern = r"^(https?|ftp)://[^\s/$.?#].[^\s]*$"

    if re.match(ip_host_pattern, url):
        return True
    if re.match(url_pattern, url):
        return True
    return False


# Función para obtener la IP pública 
def get_public_ip_address() -> str:
    """Intenta obtener la IP pública del servidor usando un servicio externo."""
    try:
        response = requests.get("https://api.ipify.org?format=json", timeout=3)
        response.raise_for_status()
        return response.json()["ip"]
    except requests.RequestException as exc:
        logger.warning("No se pudo obtener IP pública: %s", exc)
        return "desconocida"




#  CONSTRUIR Y RECARGAR CADDY

def construir_configuracion_global(*, iniciado_por: str | None = None) -> Tuple[bool, str]:
    """
    Recorre todos los UserJSON, construye un único caddy.json y llama a /load.
    Devuelve (ok, mensaje).
    """
    from .models import UserJSON                      

    pref = f"[{iniciado_por}] " if iniciado_por else ""
    logger.info(pref + "Generando configuración global de Caddy…")

    cfg: Dict[str, Any] = {
        "admin": {"listen": "127.0.0.1:2019"},
        "apps": {
            "http": {
                "servers": {
                    settings.SERVIDOR_CADDY: {"listen": [":80", ":443"], "routes": []}
                }
            }
        },
    }
    routes: List[Dict[str, Any]] = cfg["apps"]["http"]["servers"][settings.SERVIDOR_CADDY]["routes"]

    # ── /static/ ────────────────────────────────────────────────────
    if settings.STATIC_ROOT and os.path.exists(settings.STATIC_ROOT):
        routes.append({
            "match": [{"path": ["/static/*"]}],
            "handle": [{"handler": "file_server", "root": str(settings.STATIC_ROOT)}],
        })
    else:
        logger.warning("STATIC_ROOT no encontrado; se omite file_server.")

    # rutas de usuarios
    for uj in UserJSON.objects.all():
        user_routes = uj.json_data.get("apps", {}) \
                        .get("http", {}) \
                        .get("servers", {}) \
                        .get(settings.SERVIDOR_CADDY, {}) \
                        .get("routes", [])
        
        
        if user_routes:
            routes.extend(user_routes)
            logger.debug(f"Rutas de Caddy de usuario '{uj.user.username}' añadidas. Total: {len(user_routes)} rutas.")
        else:
            logger.debug(f"No hay rutas de Caddy definidas para el usuario '{uj.user.username}'.")


    # ── Catch-all → Django (Proxy inverso a tu aplicación Django) 
    # Este es el proxy inverso para cualquier petición que no haya sido gestionada por las rutas anteriores.
    # Es el "último recurso" que dirige el tráfico a tu backend Django.
    # settings.DJANGO_APP_DIAL debe ser configurado en settings.py
    django_dial_target = getattr(settings, "DJANGO_APP_DIAL", ":8000") #  puerto 8000
    routes.append({
        "handle": [{"handler": "reverse_proxy",
                    "upstreams": [{"dial": django_dial_target}]
                    }]
    })
    logger.info(f"Ruta catch-all a Django configurada con dial: '{django_dial_target}'.")


    # ── Guardar y Recargar Caddy ─────────────────────────────────────────
    # Asegura que el directorio exista para guardar el caddy.json
    os.makedirs(os.path.dirname(settings.JSON_PATH), exist_ok=True)
    try:
        with open(settings.JSON_PATH, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=4)
        logger.info(f"Configuración de Caddy guardada en: {settings.JSON_PATH}")
    except IOError as e:
        logger.critical(f"Error al escribir caddy.json en {settings.JSON_PATH}: {e}", exc_info=True)
        return False, f"Error interno del servidor al guardar la configuración: {e}"

    # Envía la configuración a la API de administración de Caddy
    try:
        # CADDY_ADMIN_URL debe apuntar al puerto de administración de Caddy (2019)
        # Asegúrate de que Django pueda alcanzar esta URL.
        r = requests.post(f"{settings.CADDY_ADMIN_URL}/load", json=cfg, timeout=10)
        r.raise_for_status() # Lanza un error para códigos de estado HTTP 4xx/5xx

        logger.info(pref + "Caddy recargado OK.")
        return True, "Caddy recargado correctamente."
    
    except requests.exceptions.Timeout:
        logger.error(pref + f"Tiempo de espera agotado al recargar Caddy en {settings.CADDY_ADMIN_URL}.")
        return False, "Error: Caddy no respondió a tiempo."
    
    except requests.exceptions.ConnectionError:
        logger.error(pref + f"No se pudo conectar con la API de Caddy en {settings.CADDY_ADMIN_URL}. ¿Está Caddy corriendo?")
        return False, "Error: No se pudo conectar con el servidor Caddy. Por favor, verifica su estado."
    
    except requests.RequestException as exc:
        # Esto capturará errores HTTP como 400, 500, etc. que raise_for_status() lanzaría
        status_code = exc.response.status_code if exc.response else "N/A"
        response_text = exc.response.text if exc.response else "No hay respuesta detallada."
        logger.error(pref + f"Caddy ERROR {status_code} – {response_text}. Detalle: {exc}")
        return False, f"Error {status_code}: {response_text}"
    
    except Exception as e:
        logger.critical(pref + f"Error inesperado durante la recarga de Caddy: {e}", exc_info=True)
        return False, f"Error inesperado al recargar Caddy: {e}"