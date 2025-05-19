
from __future__ import annotations

# ── estándar ───────────────────────────────────────────────────
import ipaddress
import os
import json
import requests
from typing import Dict, List, Tuple, Any 
import logging # Importamos el módulo de logging para rastrear eventos y errores

""" DJANGO IMPORTS """
# Importaciones estándar de Django para vistas basadas en función, autenticación, etc.
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required # Decorador para requerir login
from django.contrib.admin.views.decorators import staff_member_required # Decorador para requerir staff/superuser
# from django.utils.decorators import method_decorator # (No usado en vistas basadas en función aquí)
from django.contrib import messages # Sistema de mensajes de Django
from django.views.decorators.csrf import csrf_exempt # (Usado si deshabilitas CSRF, úsalo con precaución)
from django.utils.text import slugify


from django.conf import settings # Importamos settings para configuraciones específicas del entorno

""" API REST FRAMEWORK IMPORTS """
# Importaciones para vistas basadas en API (aunque las vistas proporcionadas son clásicas, las mantenemos por si las usas en otras partes)
# from rest_framework import status
# from rest_framework.response import Response
# from rest_framework.decorators import api_view, authentication_classes, permission_classes
# from rest_framework.authentication import TokenAuthentication
# from rest_framework.permissions import IsAuthenticated
# from rest_framework.permissions import IsAuthenticatedOrReadOnly
# from rest_framework.authtoken.models import Token
# from rest_framework.views import APIView
# from rest_framework import viewsets

""" MODELOS Y SERIALIZERS IMPORTS """
# Importamos tus modelos y serializadores personalizados
from .models import UserJSON # Modelo para almacenar el JSON de configuración de cada usuario
# from .serializers import UserRegisterSerializer # 



# --- Configuración del Logger ---
# Configura el manejo de logging en tu settings.py para ver estos mensajes 
logger = logging.getLogger(__name__)

""" 🔵🔵🔵 CONFIGURACIÓN Y FUNCIONES DE CADDY 🔵🔵🔵 """
# BASE_DIR ya está definido en settings.py y apunta a la raíz de tu proyecto backend.
# BASE_DIR = settings.BASE_DIR # (Redundante, ya está en settings)


# Directorio donde se guardará el caddy.json generado dinámicamente por Django.
DEPLOY_DIR: str = settings.DEPLOY_DIR # Se espera que DEPLOY_DIR esté definido en settings

# Ruta completa al archivo caddy.json que se genera.
# Se construye a partir del DEPLOY_DIR configurado en settings.
JSON_PATH: str = os.path.join(DEPLOY_DIR, "caddy.json")


# URL de la API de administración de Caddy. Django enviará peticiones POST a esta URL
# para recargar la configuración de Caddy.
# ¡MUY IMPORTANTE para el servidor! Debe ser la dirección y puerto ACCESIBLE por tu aplicación Django
# en el entorno del servidor. NO uses 'localhost' si Caddy no corre en la misma interfaz de red que Django.
# Ejemplo en settings.py (usando variable de entorno, muy común en despliegues):
# CADDY_ADMIN_URL = os.environ.get("CADDY_ADMIN_URL", "http://localhost:2019")
# En tu despliegue, la variable de entorno CADDY_ADMIN_URL debería estar definida
# como 'http://nombre_servicio_caddy:2019' (si usas Docker/Kubernetes) o
# 'http://ip_interna_del_servidor_caddy:2019' (si están en la misma red interna).
CADDY_URL:   str = getattr(settings, "CADDY_ADMIN_URL", "http://167.235.155.72:2019")


STATIC_ROOT: str = settings.STATIC_ROOT  # ruta a collectstatic


SERVIDOR_CADDY    = "Cloud_Guardian"


# --- Funciones de Ayuda ---

def _ip_valida(cadena: str) -> bool:
    """
    Valida si una cadena es una dirección IP (v4/v6) individual o un rango CIDR válido.
    """
    try:
        # ipaddress.ip_network validará ambos formatos. strict=False permite '/32' o '/128'.
        ipaddress.ip_network(cadena, strict=False)
        return True
    except ValueError:
        # Si ipaddress lanza un ValueError, la cadena no es un formato IP/CIDR válido.
        return False
    

def construir_configuracion_global()-> Tuple[bool, str]:
    """
    Construye la configuración completa de Caddy en formato JSON.
    Consolida:
    1) /static/* → file_server
    2) rutas de todos los usuarios (filtrando IPs/CIDR inválidos)
    3) catch-all → :8000

    Devuelve (ok, mensaje).
    """

    # --- 1. Configuración Base de Caddy ---
    cfg: Dict = {
        "admin": {"listen": "0.0.0.0:2019"},
        "apps": {
            "http": {
                "servers": {
                    SERVIDOR_CADDY: {"listen": [":80", ":443"], "routes": []}
                }
            }
        },
    }
    routes: List [Dict[str, Any]] = cfg["apps"]["http"]["servers"][SERVIDOR_CADDY]["routes"]
    
    # --- 2. Ruta para Servir Archivos Estáticos (/static/*) ---
    # Configura Caddy para servir archivos estáticos directamente desde el sistema de archivos.
    # Esto es mucho más eficiente que servirlos a través de Django/Gunicorn.
    # settings.STATIC_ROOT debe ser la ruta ABSOLUTA en el SERVIDOR donde 'collectstatic' copia los archivos.
    # Caddy debe tener permisos de LECTURA en esta ruta.
    
    if STATIC_ROOT and os.path.exists(STATIC_ROOT):
        routes.append(
            {
                "match": [{"path": ["/static/*"]}],
                "handle": [{"handler": "file_server", "root": STATIC_ROOT}],
            }
        )
    else:
        logger.warning("STATIC_ROOT no existe; se omite file_server.")



    # --- 3. Rutas de Usuario (Obtenidas de la Base de Datos) ---
    # Itera sobre la configuración JSON de Caddy guardada para cada usuario en la base de datos (en el modelo UserJSON).
    # Consolida todas estas rutas individuales en la configuración global de Caddy, filtrando entradas inválidas.
    try:
        all_user_configs = UserJSON.objects.all()
        logger.debug(f"Procesando configuraciones de {len(all_user_configs)} usuarios desde la base de datos.")

        # Itera sobre cada configuración de usuario recuperada.
        for user_json_obj in all_user_configs: # Usamos un nombre de variable claro (user_json_obj)
            # Accede a los datos JSON DEPURADOS y VALIDADOS guardados en el campo json_data del modelo UserJSON.
            # Utilizamos .get con diccionarios vacíos como default para evitar KeyErrors si la estructura no es perfecta.
            user_data: Dict[str, Any] = user_json_obj.json_data if user_json_obj.json_data is not None else {} # Aseguramos que es un dict
            user_routes_list: List[Dict[str, Any]] = (
                user_data
                    .get("apps", {})
                    .get("http", {})
                    .get("servers", {})
                    .get(SERVIDOR_CADDY, {})   # ← mismo par de llaves aquí
                    .get("routes", [])
            )


            logger.debug(f"Procesando rutas para usuario '{user_json_obj.user.username}': {len(user_routes_list)} rutas encontradas en su JSON.")

            # Itera sobre cada ruta definida en la configuración de este usuario.
            for ruta in user_routes_list:
                # Validación básica de la estructura de la ruta antes de añadirla a la configuración global.
                # Esto es CRUCIAL para prevenir que JSONs de usuario mal formados o maliciosos rompan la configuración global de Caddy.
                if not isinstance(ruta, dict) or "match" not in ruta or "handle" not in ruta:
                    logger.warning(f"[{user_json_obj.user.username}] Descartando ruta mal formada: {ruta}")
                    continue # Pasa a la siguiente ruta del usuario.

                # Validar el matcher: debe ser una lista no vacía con diccionarios dentro.
                matchers = ruta.get("match", [])
                if not isinstance(matchers, list) or not matchers or not isinstance(matchers[0], dict):
                    logger.warning(f"[{user_json_obj.user.username}] Descartando ruta con matcher inválido: {ruta}")
                    continue

                first_matcher = matchers[0] # Cogemos el primer matcher para validaciones específicas

                # Lógica específica para rutas con `remote_ip` (usada para bloqueo de IPs).
                # Filtra rangos de IP inválidos dentro de estos matchers.
                if "remote_ip" in first_matcher:
                    remote_ip_matcher = first_matcher.get("remote_ip", {})
                    ranges_list = remote_ip_matcher.get("ranges", [])
                    # Validar que 'ranges' es una lista y que cada elemento es una IP/CIDR válido.
                    if not isinstance(ranges_list, list):
                        logger.warning(f"[{user_json_obj.user.username}] Descartando ruta con remote_ip: 'ranges' no es lista: {matchers}")
                        continue

                    # Filtra y valida cada IP/CIDR en la lista de rangos.
                    valid_ranges = [rng for rng in ranges_list if _ip_valida(rng)] # Usamos la función de ayuda

                    if not valid_ranges:
                        # Si no quedan rangos IP válidos después del filtro, descarta esta ruta por completo.
                        logger.warning(f"[{user_json_obj.user.username}] Descartando ruta con remote_ip: rangos inválidos o vacíos: {matchers}")
                        continue # Pasa a la siguiente ruta del usuario.

                    # Actualiza la lista de rangos IP en el matcher con solo los válidos.
                    # Asegurar que el diccionario remote_ip existe antes de asignar la lista.
                    if "remote_ip" not in first_matcher or not isinstance(first_matcher["remote_ip"], dict):
                        first_matcher["remote_ip"] = {} # Si no existía o no era dict, lo creamos
                    first_matcher["remote_ip"]["ranges"] = valid_ranges


                # Validación adicional: asegurar que la ruta tiene al menos un path definido Y/O un remote_ip válido.
                paths = first_matcher.get("path", [])
                has_path_matcher = isinstance(paths, list) and paths # True si es lista y no vacía
                has_remote_ip_matcher = "remote_ip" in first_matcher and isinstance(first_matcher["remote_ip"].get("ranges"), list) and first_matcher["remote_ip"]["ranges"] # True si tiene remote_ip válido y no vacío

                # Si no tiene un matcher de path válido Y tampoco tiene un matcher de remote_ip válido, descartar.
                if not has_path_matcher and not has_remote_ip_matcher:
                    logger.warning(f"[{user_json_obj.user.username}] Descartando ruta sin matcher de path válido O remote_ip válido: {ruta}")
                    continue


                # Validar el handler: debe ser una lista no vacía con diccionarios dentro y tener una clave 'handler'.
                handles = ruta.get("handle", [])
                if not isinstance(handles, list) or not handles or not isinstance(handles[0], dict) or "handler" not in handles[0]:
                    logger.warning(f"[{user_json_obj.user.username}] Descartando ruta con handler inválido: {ruta}")
                    continue
                # TODO (CRÍTICO): Añadir validación aquí para asegurar que el handler es UNO PERMITIDO para usuarios.
                # Ej. solo permitir "static_response" o "reverse_proxy" a destinos internos CONTROLADOS.
                # La validación actual solo verifica la estructura básica del handler.
                # Permitir handlers como "exec" aquí sería un riesgo de seguridad ENORME.
                # Dependiendo de la funcionalidad deseada para los usuarios, esta validación es clave.


                # Si la ruta pasa todas las validaciones básicas de estructura y contenido, la añade a la lista de rutas globales.
                routes.append(ruta) # Añade la ruta válida del usuario a la lista global de rutas
                logger.debug(f"[{user_json_obj.user.username}] Añadida ruta válida de usuario: {ruta}")

    except Exception as e:
        # Captura CUALQUIER error inesperado durante el procesamiento de TODAS las configuraciones de usuario.
        # Esto es un catch-all para proteger la construcción global si algo falla al iterar, acceder a datos de un usuario, etc.
        logger.error(f"Error CRÍTICO inesperado al procesar TODAS las configuraciones de usuario para la construcción global de Caddy: {e}", exc_info=True)
        # En producción, si esto falla, las rutas de usuario no se cargarán, pero las rutas estáticas y Django SÍ.
        # Un mensaje global puede ser útil, pero solo si no interfiere con los mensajes de las vistas.
        # messages.error(None, f"Error interno crítico al procesar configuraciones de usuario para Caddy: {e}. La configuración puede estar incompleta.")


    # --- 4. Ruta "Catch-all" para Gunicorn (Django)
    routes.append(
        {
            "handle": [
                {
                    "handler": "reverse_proxy", # Handler para reenviar peticiones
                    "upstreams": [
                        # La dirección del servidor backend (Gunicorn/Django).
                        # Usamos 127.0.0.1 para loopback si Caddy y Gunicorn están en la misma máquina.
                        { "dial": ":8000" } 
                    ]
                }
            ]
        }
    )
    logger.debug("Añadido catch-all a :8000 (Gunicorn/Django).")


    # ── guardar fichero — opcional pero útil ─────────────────
    os.makedirs(DEPLOY_DIR, exist_ok=True)
    with open(JSON_PATH, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=4)
    logger.debug("📝 Guardado %s", JSON_PATH)

    # ── recargar Caddy ───────────────────────────────────────
    try:
        resp = requests.post(f"{CADDY_URL}/load", json=cfg, timeout=10)
        if resp.ok:
            logger.info("✅ Caddy recargado.")
            return True, "Caddy recargado correctamente."
        logger.error("❌ Caddy devolvió %s – %s", resp.status_code, resp.text)
        return False, f"Error {resp.status_code}: {resp.text}"
    except requests.exceptions.RequestException as exc:
        logger.error("❌ No se pudo contactar con Caddy: %s", exc)
        return False, f"No se pudo contactar con Caddy: {exc}"

""" 🔵 VISTAS CLÁSICAS PARA TEMPLATES 🔵 """

# Sugerencia para futuras mejoras:
# Considera reemplazar el manejo manual de request.POST con Django Forms.
# Los formularios de Django automatizan la limpieza, validación y manejo de errores,
# haciendo el código de las vistas más limpio y seguro.

""" FUNCIONES DE SUPERUSUARIO: PARA ELIMINAR USUARIOS """
@staff_member_required # Solo usuarios marcados como staff (incluye superusuarios) pueden acceder
def eliminar_usuario(request):
    """
    Vista para que un superusuario pueda eliminar usuarios de la aplicación.
    Después de eliminar un usuario, reconstruye y recarga la configuración global de Caddy
    para eliminar las rutas asociadas a ese usuario.
    """
    # Solo procesamos peticiones POST para eliminar
    if request.method == "POST":
        # Obtenemos el nombre de usuario del formulario POST.
        username = request.POST.get("username", "").strip()

        # Validación básica: el nombre de usuario no debe estar vacío.
        if not username:
            messages.warning(request, "Debes introducir el nombre de usuario a eliminar.")
            # Redirige de vuelta a la misma página para mostrar el mensaje
            return redirect("eliminar_usuario")

        try:
            # Intenta obtener el usuario de la base de datos.
            user = User.objects.get(username=username)
            # Validación de seguridad: no permitir que un superusuario se elimine a sí mismo o a otro superusuario.
            if user.is_superuser:
                messages.error(request, "No puedes eliminar un superusuario.")
                logger.warning(f"Intento de superusuario '{request.user.username}' de eliminar a otro superusuario: '{username}'.")
            else:
                # Elimina el usuario. Gracias a on_delete=CASCADE en el modelo UserJSON,
                # la configuración de Caddy asociada a este usuario también se eliminará automáticamente.
                user.delete()
                logger.info(f"Superusuario '{request.user.username}' eliminó al usuario: '{username}'.")

                # Después de eliminar al usuario (y su configuración JSON asociada en cascada),
                # reconstruye la configuración global de Caddy (que ahora no incluirá las rutas del usuario eliminado)
                # y solicita a Caddy que la recargue.
                ok, msg = construir_configuracion_global()
                # Muestra un mensaje de éxito o error basado en si la recarga de Caddy fue exitosa.
                messages.success(request, f"Usuario '{username}' eliminado. {msg}" if ok else f"Usuario eliminado, pero {msg}")
                logger.info(f"Resultado de recarga de Caddy tras eliminar usuario '{username}': {msg}")

        except User.DoesNotExist:
            # Maneja el caso en que el nombre de usuario no existe en la base de datos.
            messages.error(request, f"No existe el usuario '{username}'.")
            logger.warning(f"Superusuario '{request.user.username}' intentó eliminar un usuario no existente: '{username}'.")
        except Exception as e:
            # Captura cualquier otro error durante el proceso de eliminación.
            messages.error(request, f"Ocurrió un error al intentar eliminar al usuario '{username}': {e}")
            logger.error(f"Error inesperado eliminando usuario '{username}' por '{request.user.username}': {e}", exc_info=True)

        # Siempre redirige al final de una petición POST exitosa o fallida (para evitar reenvío del formulario).
        return redirect("eliminar_usuario")

    # Para peticiones GET, simplemente renderiza el template del formulario de eliminación.
    return render(request, "eliminar_usuario.html")

"""  HOME (DASHBOARD)  """
@login_required # Solo usuarios autenticados pueden acceder
def home(request):
    """
    Vista principal del dashboard para usuarios autenticados.
    Simplemente renderiza el template de la página de inicio.
    """
    logger.debug(f"Usuario '{request.user.username}' accediendo a la página de inicio.")
    return render(request, "home.html")

# Las vistas de Login y Register no requieren autenticación previa.

"""  LOGIN  """
def login_view(request):
    """
    Vista para manejar el inicio de sesión de usuarios.
    Si el usuario ya está autenticado, lo redirige al home.
    """
    # Si el usuario ya ha iniciado sesión, lo redirigimos al home para evitar mostrar el formulario de login.
    if request.user.is_authenticated:
        logger.debug(f"Usuario autenticado '{request.user.username}' intentó acceder al login, redirigiendo a home.")
        return redirect('home')

    # Procesa el formulario de inicio de sesión si la petición es POST.
    if request.method == "POST":
        # Obtiene el nombre de usuario y la contraseña del formulario, eliminando espacios en blanco.
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "").strip()

        # Validación básica: ambos campos son obligatorios.
        if not username or not password:
            messages.warning(request, "Debes introducir usuario y contraseña.")
            # Renderiza el template de login de nuevo, opcionalmente pasando el username para que no tenga que reescribirlo.
            return render(request, "login.html", {"username": username})

        # Autentica al usuario usando el backend de autenticación de Django.
        user = authenticate(request, username=username, password=password)

        # Verifica si la autenticación fue exitosa.
        if user:
            # Si el usuario existe y la contraseña es correcta, inicia la sesión.
            auth_login(request, user)
            messages.success(request, f"Bienvenido {username}!")
            logger.info(f"Usuario '{username}' ha iniciado sesión correctamente.")
            # Redirige al usuario. Si hay un parámetro 'next' en la URL (ej. /login/?next=/config), va allí.
            # De lo contrario, redirige a la página 'home'.
            next_url = request.GET.get('next', 'home')
            return redirect(next_url)
        else:
            # Si la autenticación falla (usuario o contraseña incorrectos).
            messages.error(request, "Usuario o contraseña incorrectos.")
            logger.warning(f"Intento de inicio de sesión fallido para usuario: '{username}'.")
            # Renderiza el template de login de nuevo.
            return render(request, "login.html", {"username": username})

    # Para peticiones GET, simplemente renderiza el template del formulario de login.
    logger.debug("Mostrando formulario de login.")
    return render(request, "login.html")


"""  REGISTER  """
def register_view(request):
    """
    Vista para manejar el registro de nuevos usuarios.
    Si el usuario ya está autenticado, lo redirige al home.
    Crea un usuario de Django y su configuración inicial de Caddy (UserJSON).
    """
    # Si el usuario ya ha iniciado sesión, lo redirigimos al home.
    if request.user.is_authenticated:
        logger.debug(f"Usuario autenticado '{request.user.username}' intentó acceder al registro, redirigiendo a home.")
        return redirect('home')

    # Procesa el formulario de registro si la petición es POST.
    if request.method == "POST":
        # Obtiene los datos del formulario, limpiando espacios en blanco.
        username = request.POST.get("username", "").strip()
        password1 = request.POST.get("password1", "").strip()
        password2 = request.POST.get("password2", "").strip()

        # Validación básica: todos los campos son obligatorios.
        if not username or not password1 or not password2:
            messages.warning(request, "Todos los campos son obligatorios.")
            # Renderiza de nuevo el formulario, manteniendo el nombre de usuario.
            return render(request, "register.html", {"username": username})

        # Validación: las contraseñas deben coincidir.
        if password1 != password2:
            messages.error(request, "Las contraseñas no coinciden.")
            return render(request, "register.html", {"username": username}) # Podrías querer no mantener las contraseñas por seguridad

        # Validación: el nombre de usuario no debe existir ya.
        if User.objects.filter(username=username).exists():
            messages.error(request, f"El nombre de usuario '{username}' ya existe.")
            return render(request, "register.html", {"username": username})

        # Si todas las validaciones pasan, intentamos crear el usuario y su configuración.
        try:
            # Crea el usuario de Django usando el método recomendado `create_user`.
            user = User.objects.create_user(username=username, password=password1)
            logger.info(f"Nuevo usuario de Django creado: '{username}'.")

            # --- Creación de la Configuración Inicial de Caddy para el Usuario ---
            # Define la estructura JSON básica para la configuración individual de este nuevo usuario en Caddy.
            # Inicialmente, la lista de rutas estará vacía. Las vistas posteriores (IPs, Rutas Protegidas) la modificarán.
            default_config_json = {
                "apps": {
                    "http": {
                        "servers": {
                            "Cloud_Guardian": {
                                # Los puertos 'listen' en la config individual no son tan relevantes como en la global,
                                # ya que la config global consolidada es la que usa Caddy. Esto es más un marcador.
                                "listen": [":80"],
                                "routes": [] # Lista vacía inicialmente.
                            }
                        }
                    }
                }
            }
            # Crea el objeto UserJSON asociado al nuevo usuario y guarda la configuración JSON inicial.
            UserJSON.objects.create(user=user, json_data=default_config_json)
            messages.success(request, f"Usuario '{username}' registrado y configuración inicial creada!")
            logger.info(f"Configuración inicial de Caddy (UserJSON) creada para el usuario '{username}'.")

            # --- Opcional: Recargar Caddy Inmediatamente Tras el Registro ---
            # Considera si esto es necesario. Podría ser ineficiente si hay muchos registros rápidos.
            # Si Caddy recarga periódicamente o los cambios solo se aplican al siguiente inicio de Caddy,
            # puedes comentar las siguientes líneas.
            # logger.info(f"Llamando a construir_configuracion_global tras registro de '{username}'.")
            # ok, msg = construir_configuracion_global()
            # logger.info(f"Resultado de recarga de Caddy tras registro de '{username}': {msg}")
            # if not ok:
            #      messages.warning(request, f"Usuario registrado, pero hubo un problema al recargar Caddy: {msg}")


            # Inicia sesión automáticamente con el usuario recién registrado.
            auth_login(request, user)
            # Redirige al home después del registro e inicio de sesión exitosos.
            return redirect("home")

        except Exception as e:
            # Captura cualquier error que ocurra durante la creación del usuario o UserJSON.
            logger.error(f"Error durante el registro del usuario '{username}': {e}", exc_info=True)
            messages.error(request, f"Ocurrió un error durante el registro: {e}")
            # Si el usuario de Django se creó pero falló la creación del UserJSON,
            # es una buena práctica eliminar el usuario de Django para mantener la consistencia.
            # Verificamos si la variable 'user' existe y tiene una clave primaria (pk).
            if 'user' in locals() and user.pk:
                try:
                    user.delete() # Intenta eliminar el usuario creado incompletamente.
                    logger.warning(f"Usuario '{username}' creado, pero eliminado debido a un fallo posterior (ej. en UserJSON).")
                    messages.error(request, f"Usuario '{username}' creado, pero falló la configuración inicial. Por favor, intenta registrarte de nuevo.")
                except Exception as delete_e:
                    logger.error(f"Error al limpiar usuario '{username}' después de un error de registro: {delete_e}", exc_info=True)
                    messages.error(request, f"Usuario '{username}' creado, pero falló la configuración inicial y la limpieza. Contacta al administrador.")


            # Renderiza el formulario de registro de nuevo, mostrando el error.
            return render(request, "register.html", {"username": username})

    # Para peticiones GET, simplemente renderiza el template del formulario de registro.
    logger.debug("Mostrando formulario de registro.")
    return render(request, "register.html")


"""  LOGOUT (cerrar sesión) """
@login_required # Solo usuarios autenticados pueden cerrar sesión
def logout_view(request):
    """
    Vista para cerrar la sesión del usuario autenticado.
    """
    logger.info(f"Usuario '{request.user.username}' cerrando sesión.")
    # Cierra la sesión del usuario actual.
    auth_logout(request)
    messages.success(request, "Sesión cerrada correctamente.")
    # Redirige a la página de login después de cerrar sesión.
    return redirect('login')


"""  CONFIGURACIÓN GENERAL  """
@login_required # Solo usuarios autenticados pueden acceder a la configuración
def configuracion(request):
    """
    Vista para ver y, opcionalmente, editar la configuración de Caddy.
    - Los superusuarios pueden ver y editar la configuración global COMPLETA (el caddy.json final).
    - Los usuarios normales pueden ver y editar ÚNICAMENTE su parte de la configuración (su UserJSON).
    Después de guardar cambios, se intenta recargar Caddy con la configuración actualizada.
    """
    # Verifica si el usuario actual es un superusuario.
    is_superuser = request.user.is_superuser
    config_json = "" # Variable para almacenar la configuración (como string JSON formateado) a mostrar.
    json_error = False # Bandera para indicar si hubo un error al leer el JSON.

    # --- Lógica para Superusuarios ---
    if is_superuser:
        logger.debug(f"Superusuario '{request.user.username}' accediendo a la configuración global.")
        try:
            # Intenta leer el archivo caddy.json global del servidor.
            # Asegúrate de que Django tenga permisos de LECTURA en JSON_PATH.
            with open(JSON_PATH, "r", encoding="utf-8") as f:
                global_config = json.load(f)
            # Formatea el JSON para mostrarlo en el template.
            config_json = json.dumps(global_config, indent=4)
            logger.debug(f"Leído caddy.json global de {JSON_PATH}.")

            # Si la petición es POST, el superusuario ha enviado una configuración editada.
            if request.method == "POST":
                # Obtiene el texto del JSON enviado en el formulario.
                new_config_str = request.POST.get("config", "").strip()
                logger.info(f"Superusuario '{request.user.username}' intentando actualizar la configuración global.")

                try:
                    # Intenta parsear el texto recibido como JSON.
                    data = json.loads(new_config_str)

                    # TODO (Opcional): Añadir validación más estricta aquí para superusuarios.
                    # Aunque son superusuarios, podrías querer validar que el JSON sigue
                    # una estructura básica esperada para evitar errores graves en Caddy.

                    # Si el JSON es válido, lo guarda SOBREESCRIBIENDO el archivo caddy.json global.
                    # Django necesita permisos de ESCRITURA en JSON_PATH.
                    with open(JSON_PATH, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=4)
                    logger.info(f"Archivo caddy.json global actualizado en {JSON_PATH}.")

                    # Llama a la función para reconstruir la configuración global (que leerá el archivo recién guardado)
                    # y solicitar la recarga a Caddy.
                    # La función `construir_configuracion_global` ya maneja la recarga por API y devuelve su resultado.
                    ok, msg = construir_configuracion_global()
                    # Muestra un mensaje de éxito o error basado en el resultado de la recarga de Caddy.
                    if ok:
                        messages.success(request, f"Configuración global actualizada y recargada correctamente. {msg}")
                        logger.info(f"Recarga de Caddy exitosa tras actualización global por superusuario '{request.user.username}'.")
                    else:
                        # Si la recarga falla, mostramos el mensaje de error de Caddy/requests.
                        messages.error(request, f"Configuración global actualizada, pero {msg}")
                        logger.warning(f"Fallo en la recarga de Caddy tras actualización global por superusuario '{request.user.username}': {msg}")

                except json.JSONDecodeError:
                    # Maneja el caso en que el texto recibido no es un JSON válido.
                    messages.error(request, "Formato JSON inválido enviado.")
                    logger.warning(f"Superusuario '{request.user.username}' envió JSON inválido para configuración global.")
                    json_error = True # Indica que el JSON enviado era inválido.
                    config_json = new_config_str # Muestra el JSON inválido que envió el usuario para que lo corrija.
                except Exception as e:
                    # Captura cualquier otro error durante el proceso de guardado o recarga.
                    messages.error(request, f"Error al guardar o recargar la configuración global: {e}")
                    logger.error(f"Error al actualizar configuración global por '{request.user.username}': {e}", exc_info=True)
                    # Intenta volver a leer el archivo por si acaso el error no fue al escribir
                    try:
                        with open(JSON_PATH, "r", encoding="utf-8") as f:
                            global_config = json.load(f)
                        config_json = json.dumps(global_config, indent=4)
                    except Exception as read_err:
                        logger.error(f"Error re-leyendo caddy.json después de error POST: {read_err}")
                        messages.warning(request, "Error re-leyendo el archivo de configuración después del intento de actualización.")


                # En lugar de redirigir, volvemos a renderizar la misma página para que el superusuario vea el resultado,
                # incluyendo el JSON actual (ya sea el guardado o el inválido que intentó enviar).
                return render(request, "configuracion.html", {
                    "config": config_json,
                    "es_superuser": True,
                    "json_error": json_error # Pasa el estado de error de JSON al template.
                })


        except FileNotFoundError:
            # Maneja el caso en que el archivo caddy.json no existe en la ruta esperada.
            messages.warning(request, f"El archivo de configuración global '{JSON_PATH}' no se encontró en el servidor. Se creará uno al recargar Caddy o al guardar desde aquí.")
            config_json = "{}" # Muestra un JSON vacío o una estructura base por defecto en el template.
            logger.warning(f"Archivo caddy.json global no encontrado en {JSON_PATH} para superusuario '{request.user.username}'.")
            if request.method == "POST": # Si intentó guardar un archivo que no existía
                messages.error(request, "No se pudo guardar la configuración: el directorio DEPLOY_DIR puede no existir o no tener permisos de escritura.")
                logger.error(f"Intento de guardar caddy.json falló para '{request.user.username}': Directorio {DEPLOY_DIR} no existe o sin permisos?", exc_info=True)

            # Renderiza el template mostrando el estado actual (archivo no encontrado).
            return render(request, "configuracion.html", {
                "config": config_json,
                "es_superuser": True
            })

        except json.JSONDecodeError:
            # Maneja el caso en que el archivo caddy.json existe pero contiene JSON inválido.
            messages.error(request, f"El archivo de configuración global '{JSON_PATH}' contiene JSON inválido. Por favor, corrígelo manualmente en el servidor si es necesario.")
            logger.error(f"El archivo {JSON_PATH} contiene JSON inválido para superusuario '{request.user.username}'.")
            config_json = "" # Muestra un campo vacío o indica un error grave en el template.
            json_error = True # Indica que el archivo tiene un error de JSON.
            # Renderiza el template indicando el error.
            return render(request, "configuracion.html", {
                "config": config_json,
                "es_superuser": True,
                "json_error": True # Pasa el estado de error al template.
            })

        except Exception as e:
            # Captura cualquier otro error inesperado al intentar leer el archivo.
            messages.error(request, f"Error inesperado al leer el caddy.json global: {e}")
            logger.error(f"Error inesperado al leer caddy.json global para superusuario '{request.user.username}': {e}", exc_info=True)
            # Redirige a home si ocurre un error grave al cargar la página.
            return redirect("home")

    # --- Lógica para Usuarios Normales ---
    else: # Si el usuario NO es superusuario.
        logger.debug(f"Usuario normal '{request.user.username}' accediendo a su configuración.")
        try:
            # Intenta obtener el objeto UserJSON para el usuario actual.
            # get_or_create lo recuperará si existe o creará uno nuevo si no.
            user_config, created = UserJSON.objects.get_or_create(user=request.user)
            if created:
                # Si el objeto UserJSON se acaba de crear, lo inicializamos con una estructura JSON básica.
                logger.info(f"UserJSON creado automáticamente para el usuario '{request.user.username}' (no existía previamente).")
                # Verificamos explícitamente si json_data está vacío, aunque get_or_create sin defaults debería dejarlo {}
                if not user_config.json_data:
                    user_config.json_data = {
                        "apps": {
                            "http": {
                                "servers": {
                                    "Cloud_Guardian": {
                                        "listen": [":80"], # Marcador
                                        "routes": [] # Empieza con rutas vacías.
                                    }
                                }
                            }
                        }
                    }
                    # Guardamos el objeto recién creado con la estructura inicial.
                    user_config.save()
                    logger.debug(f"Inicializado json_data para nuevo UserJSON de '{request.user.username}'.")


        except Exception as e:
            # Captura errores al intentar obtener o crear el objeto UserJSON.
            messages.error(request, f"Error al obtener la configuración del usuario: {e}")
            logger.error(f"Error al obtener/crear UserJSON para '{request.user.username}': {e}", exc_info=True)
            # Redirige a home si no se puede cargar la configuración del usuario.
            return redirect("home")

        # Si la petición es POST, el usuario normal ha enviado su configuración editada.
        if request.method == "POST":
            # Obtiene el texto del JSON enviado en el formulario.
            new_config_str = request.POST.get("config", "").strip()
            logger.info(f"Usuario '{request.user.username}' intentando actualizar su configuración JSON.")

            try:
                # Intenta parsear el texto recibido como JSON.
                data = json.loads(new_config_str)

                # TODO (CRÍTICO): Añadir validación ESTRICTA aquí para usuarios normales.
                # Un usuario normal NO debería poder modificar cualquier parte del JSON de Caddy (ej. los puertos 'listen',
                # la configuración 'admin', o añadir rutas que no estén bajo su prefijo /username/).
                # Actualmente, esta vista permite al usuario normal enviar *cualquier* JSON válido,
                # lo cual es un riesgo de seguridad y estabilidad.
                # Deberías validar que 'data' tiene la estructura esperada y solo permitir modificaciones
                # en secciones específicas, como la lista de rutas 'routes'.
                #
                # Validación básica actual (solo verifica que la estructura principal existe):
                if not isinstance(data, dict) or "apps" not in data or "http" not in data.get("apps", {}) or \
                "servers" not in data.get("apps", {}).get("http", {}) or \
                "Cloud_Guardian" not in data.get("apps", {}).get("http", {}).get("servers", {}):
                    messages.error(request, "Estructura JSON de configuración inválida. La estructura básica esperada no se encontró.")
                    logger.warning(f"Usuario '{request.user.username}' envió JSON con estructura inválida.")
                    json_error = True # Indica que el JSON enviado era inválido.
                    config_json = new_config_str # Muestra el JSON inválido enviado.
                    # Renderiza la página de configuración de nuevo con el JSON inválido.
                    return render(request, "configuracion.html", {
                        "config": config_json,
                        "es_superuser": False,
                        "json_error": json_error # Pasa el estado de error al template.
                    })
                # TODO: Añadir aquí validaciones más granulares sobre QUÉ se puede modificar dentro del JSON.


                # Si el JSON es válido (según las validaciones implementadas), lo guarda en el campo json_data del UserJSON.
                user_config.json_data = data
                # Guarda el objeto UserJSON actualizado en la base de datos.
                user_config.save()
                logger.info(f"Configuración JSON guardada en base de datos para usuario '{request.user.username}'.")

                # Llama a la función para reconstruir la configuración global de Caddy (que leerá la base de datos,
                # incluyendo el UserJSON recién actualizado) y solicita la recarga a Caddy.
                ok, msg = construir_configuracion_global()
                # Muestra un mensaje de éxito o error basado en el resultado de la recarga de Caddy.
                (messages.success if ok else messages.error)(
                    request,
                    msg # El mensaje ya indica si se guardó y recargó, o si falló la recarga.
                )
                logger.info(f"Resultado de recarga de Caddy tras actualización de configuración de '{request.user.username}': {msg}")

                # Redirige a la misma página de configuración después del guardado y recarga.
                # Esto evita el reenvío del formulario al recargar la página en el navegador.
                return redirect("configuracion")

            except json.JSONDecodeError:
                # Maneja el caso en que el texto recibido no es un JSON válido.
                messages.error(request, "Formato JSON inválido enviado.")
                logger.warning(f"Usuario '{request.user.username}' envió JSON inválido para su configuración.")
                json_error = True # Indica que el JSON enviado era inválido.
                config_json = new_config_str # Muestra el JSON inválido que envió el usuario.
                # Renderiza la página de configuración de nuevo con el JSON inválido.
                return render(request, "configuracion.html", {
                    "config": config_json,
                    "es_superuser": False,
                    "json_error": json_error # Pasa el estado de error al template.
                })
            except Exception as e:
                # Captura cualquier otro error durante el proceso de guardado o recarga.
                messages.error(request, f"Error al procesar la configuración: {e}")
                logger.error(f"Error al procesar configuración de '{request.user.username}': {e}", exc_info=True)
                json_error = True # Indica que hubo un error.
                config_json = new_config_str # Muestra el último JSON intentado.
                # Renderiza la página de configuración de nuevo con el error.
                return render(request, "configuracion.html", {
                    "config": config_json,
                    "es_superuser": False,
                    "json_error": json_error # Pasa el estado de error al template.
                })

        # Si la petición es GET (o POST fallido y re-renderizado), mostramos la configuración JSON actual del usuario.
        # Aseguramos que user_config.json_data tiene un valor por defecto si es None por alguna razón inesperada.
        user_data = user_config.json_data if user_config.json_data is not None else {}
        config_json = json.dumps(user_data, indent=4)
        # Renderiza el template de configuración para usuarios normales.
        return render(request, "configuracion.html", {
            "config": config_json,
            "es_superuser": False
        })


"""  IPs BLOQUEADAS  """
@login_required # Solo usuarios autenticados pueden gestionar sus IPs bloqueadas
def ips_bloqueadas(request):
    """
    Vista para que un usuario gestione la lista de direcciones IP o rangos CIDR que quiere bloquear
    para el acceso a las rutas bajo su prefijo /<username>/.
    Modifica el JSON de configuración del usuario y reconstruye la configuración global de Caddy.
    """
    logger.debug(f"Usuario '{request.user.username}' accediendo a IPs bloqueadas.")

    try:
        # Obtiene o crea el objeto UserJSON para el usuario actual.
        user_config, created = UserJSON.objects.get_or_create(user=request.user)
        if created:
            logger.info(f"UserJSON creado automáticamente para el usuario '{request.user.username}' (no existía en ips_bloqueadas).")
            # Inicializa con estructura básica si es nuevo y no tiene data.
            if not user_config.json_data:
                user_config.json_data = {
                    "apps": {"http": {"servers": {"Cloud_Guardian": {"listen": [":80"], "routes": []}}}}
                }
                user_config.save()
                logger.debug(f"Inicializado json_data para nuevo UserJSON de '{request.user.username}' en ips_bloqueadas.")


        # Obtiene los datos JSON de la configuración del usuario.
        data = user_config.json_data

    except Exception as e:
        # Captura errores al obtener/crear el UserJSON.
        messages.error(request, f"Error al obtener la configuración del usuario: {e}")
        logger.error(f"Error al obtener UserJSON en ips_bloqueadas para '{request.user.username}': {e}", exc_info=True)
        # Redirige a home si ocurre un error grave.
        return redirect("home")

    # --- Preparación de Datos y Búsqueda de la Ruta de Bloqueo de IP ---
    # Asegura que la estructura JSON necesaria existe en los datos del usuario y obtiene la lista de rutas.
    apps = data.setdefault("apps", {})
    http = apps.setdefault("http", {})
    servers = http.setdefault("servers", {})
    cloud_guardian = servers.setdefault("Cloud_Guardian", {})
    # 'rutas' es ahora una referencia a la lista `routes` dentro de `data`.
    rutas = cloud_guardian.setdefault("routes", [])

    # Intenta encontrar la ruta específica en el JSON del usuario que usamos para bloquear IPs.
    # La identificamos por:
    # 1. Tener un matcher con un path que empieza con '/<username>/'.
    # 2. Tener un matcher 'remote_ip'.
    # 3. Tener un handler de tipo 'static_response' con status_code 403.
    ruta_ip_bloqueo = None
    # Iteramos sobre una copia de la lista de rutas para evitar problemas si la modificamos mientras iteramos.
    for r in list(rutas):
        matchers = r.get("match", [])
        # Verificamos si hay matchers y el primero cumple nuestras condiciones de identificación.
        if matchers:
            first_matcher = matchers[0]
            # 1. Verifica si tiene un path que empieza con el prefijo del usuario.
            path_matches_prefix = any(p.startswith(f"/{request.user.username}/") for p in first_matcher.get("path", []))
            # 2. Verifica si tiene un matcher 'remote_ip'.
            has_remote_ip_matcher = "remote_ip" in first_matcher
            # 3. Verifica si tiene el handler 'static_response' con status 403.
            is_403_static_response = (
                r.get("handle", [{}])[0].get("handler") == "static_response" and
                r.get("handle", [{}])[0].get("status_code") == 403
            )

            # Si cumple las 3 condiciones, hemos encontrado la ruta de bloqueo de IP.
            if path_matches_prefix and has_remote_ip_matcher and is_403_static_response:
                ruta_ip_bloqueo = r
                logger.debug(f"Ruta de bloqueo de IP existente encontrada para '{request.user.username}'.")
                break # Asumimos que solo hay una ruta de este tipo por usuario para simplificar.

    # Inicializa la lista de IPs bloqueadas (deny_ips).
    # Si encontramos la ruta de bloqueo, extraemos sus rangos de IP.
    deny_ips = []
    if ruta_ip_bloqueo:
        deny_ips = ruta_ip_bloqueo["match"][0]["remote_ip"].get("ranges", [])
        # Limpiamos la lista de IPs obtenida para asegurar que solo contiene formatos válidos,
        # por si el JSON guardado previamente contenía entradas corruptas.
        deny_ips = [ip for ip in deny_ips if _ip_valida(ip)]
        logger.debug(f"IPs bloqueadas cargadas para '{request.user.username}': {deny_ips}")


    # --- Procesamiento de Peticiones POST (Añadir/Eliminar IPs) ---
    if request.method == "POST":
        # Obtiene la acción solicitada (add o delete) y las IPs del formulario.
        action = request.POST.get("action")
        ip_add = request.POST.get("ip_add", "").strip()
        ip_del = request.POST.get("ip_delete", "").strip()

        logger.info(f"Usuario '{request.user.username}' intentando acción '{action}' en IPs bloqueadas (IP add: '{ip_add}', IP del: '{ip_del}').")

        # --- Lógica para Añadir IP ---
        if action == "add":
            if not ip_add:
                messages.warning(request, "Debes introducir la IP/CIDR a bloquear.")
            elif not _ip_valida(ip_add):
                # Valida el formato de la IP/CIDR a añadir.
                messages.error(request, f"«{ip_add}» no es una dirección IP o rango CIDR válida.")
                logger.warning(f"Usuario '{request.user.username}' intentó añadir IP/CIDR inválido: '{ip_add}'")
            elif ip_add in deny_ips:
                # Verifica si la IP/CIDR ya está en la lista.
                messages.info(request, f"La IP/CIDR {ip_add} ya estaba bloqueada.")
                logger.info(f"Usuario '{request.user.username}' intentó añadir IP/CIDR ya bloqueado: '{ip_add}'")
            else:
                # Si la IP es válida y no está duplicada, la añade a la lista.
                deny_ips.append(ip_add)
                messages.success(request, f"Dirección IP/CIDR {ip_add} añadido para bloqueo.")
                logger.info(f"Usuario '{request.user.username}' añadió IP/CIDR a la lista de bloqueo: '{ip_add}'")


        # --- Lógica para Eliminar IP ---
        elif action == "delete":
            if not ip_del:
                messages.warning(request, "Debes introducir la IP/CIDR a desbloquear.")
            elif not _ip_valida(ip_del): # Opcional: podrías querer validar el formato también al eliminar.
                messages.error(request, f"«{ip_del}» no es una dirección IP o rango CIDR válida.")
                logger.warning(f"Usuario '{request.user.username}' intentó eliminar IP/CIDR con formato inválido: '{ip_del}'")
            elif ip_del not in deny_ips:
                # Verifica si la IP/CIDR está en la lista para poder eliminarla.
                messages.warning(request, f"La IP/CIDR {ip_del} no estaba bloqueada.")
                logger.info(f"Usuario '{request.user.username}' intentó eliminar IP/CIDR no bloqueado: '{ip_del}'")
            else:
                # Si la IP está en la lista, la elimina.
                deny_ips.remove(ip_del)
                messages.success(request, f"Dirección IP/CIDR {ip_del} eliminado del bloqueo.")
                logger.info(f"Usuario '{request.user.username}' eliminó IP/CIDR del bloqueo: '{ip_del}'")

        # --- Actualización de la Configuración del Usuario y Recarga de Caddy ---
        # Si se realizó una acción válida (se proporcionó una IP para añadir o eliminar), actualizamos el JSON del usuario
        # y reconstruimos/recargamos la configuración global de Caddy.
        if action in {"add", "delete"} and (ip_add if action == "add" else ip_del): # Condición para asegurar que hubo un input válido
            # Construimos la estructura de la ruta de bloqueo de IP basada en la lista `deny_ips` actual.
            if deny_ips: # Si hay IPs para bloquear en la lista...
                nueva_ruta_bloqueo = {
                    "match": [{
                        # Esta ruta coincidirá con cualquier petición cuyo path empiece con /<username>/
                        "path": [f"/{request.user.username}/*"],
                        # ...Y cuya IP de origen esté en la lista de rangos `deny_ips`.
                        "remote_ip": {"ranges": deny_ips}
                    }],
                    "handle": [{
                        # Si coincide, Caddy responderá con un estado 403 (Prohibido) y un cuerpo de texto simple.
                        "handler": "static_response",
                        "status_code": 403,
                        "body": "IP bloqueada por Cloud Guardian" # Mensaje más informativo
                    }]
                }
                # Buscamos si ya existía una ruta de bloqueo de IP para este usuario (identificada arriba).
                if ruta_ip_bloqueo:
                    # Si existía, reemplazamos la ruta vieja por la nueva con la lista de IPs actualizada.
                    try:
                        idx = rutas.index(ruta_ip_bloqueo) # Encuentra el índice de la ruta vieja.
                        rutas[idx] = nueva_ruta_bloqueo # Reemplaza la ruta en la lista `rutas` (que es una referencia a `data`).
                        logger.debug(f"Ruta de bloqueo de IP existente actualizada para '{request.user.username}'.")
                    except ValueError:
                        # Esto no debería ocurrir si ruta_ip_bloqueo fue encontrado en la lista original 'rutas'.
                        # Es un fallback por si acaso la lista cambió inesperadamente entre la búsqueda y el reemplazo.
                        logger.error(f"Error interno: Ruta de bloqueo de IP no encontrada en la lista original para reemplazo en '{request.user.username}'. Añadiendo como nueva.")
                        rutas.insert(0, nueva_ruta_bloqueo) # Añadir al principio si no se pudo reemplazar.
                else:
                    # Si no existía una ruta de bloqueo de IP para este usuario, la añadimos al principio de la lista de rutas del usuario.
                    # Añadirla al principio asegura que Caddy la evalúe antes que otras rutas genéricas o el catch-all.
                    rutas.insert(0, nueva_ruta_bloqueo)
                    logger.debug(f"Ruta de bloqueo de IP creada y añadida para '{request.user.username}'.")

            else: # Si la lista de IPs bloqueadas (deny_ips) está vacía...
                # ...y si existía una ruta de bloqueo de IP para este usuario, la eliminamos.
                if ruta_ip_bloqueo:
                    try:
                        # Eliminamos la ruta de bloqueo de la lista de rutas del usuario.
                        rutas.remove(ruta_ip_bloqueo)
                        logger.debug(f"Ruta de bloqueo de IP eliminada porque la lista está vacía para '{request.user.username}'.")
                    except ValueError:
                        # Fallback si no se encuentra la ruta aunque creíamos que existía.
                        logger.error(f"Error interno: Ruta de bloqueo de IP no encontrada en la lista original para eliminación en '{request.user.username}'.")


            # --- Guardar Cambios en la Base de Datos y Recargar Caddy ---
            # Los cambios ya están en el diccionario `data` (ya que 'rutas' es una referencia a una lista dentro de 'data').
            # Asignamos explícitamente data a user_config.json_data (aunque a menudo no es estrictamente necesario si se modificó in-place)
            # y guardamos el objeto UserJSON en la base de datos.
            user_config.json_data = data
            try:
                user_config.save() # Persiste los cambios en la base de datos.
                logger.info(f"Configuración de IPs bloqueadas guardada en DB para usuario '{request.user.username}'.")

                # Llama a la función global para reconstruir la configuración completa de Caddy
                # (que ahora incluirá la configuración actualizada del usuario) y recargar Caddy.
                ok, msg = construir_configuracion_global()
                # Muestra un mensaje de éxito o error basado en si la recarga de Caddy fue exitosa.
                (messages.success if ok else messages.error)(
                    request,
                    f"Operación completada. {msg}" if ok
                    # Si la recarga falla, indicamos que los cambios se guardaron en la DB, pero Caddy no los aplicó.
                    else f"Cambios guardados en la base de datos, pero {msg}"
                )
                logger.info(f"Resultado de recarga de Caddy tras actualización de IPs bloqueadas de '{request.user.username}': {msg}")

            except Exception as e:
                # Captura errores durante el proceso de guardado en la DB o la recarga de Caddy.
                messages.error(request, f"Error al guardar la configuración de IPs bloqueadas: {e}")
                logger.error(f"Error al guardar UserJSON o recargar Caddy para '{request.user.username}' (ips_bloqueadas POST): {e}", exc_info=True)


            # Redirige a la misma página después del procesamiento POST para evitar el reenvío del formulario
            # y para mostrar el estado actual (la lista de IPs bloqueadas actualizada).
            return redirect("ips_bloqueadas")


    # --- Renderizar la Página (para peticiones GET o después de POST) ---
    # Prepara la lista de IPs bloqueadas para mostrarla en el template.
    # Solo incluimos las IPs que son válidas según nuestra función de validación.
    display_deny_ips = [ip for ip in deny_ips if _ip_valida(ip)]
    logger.debug(f"Renderizando página de IPs bloqueadas para '{request.user.username}' con IPs: {display_deny_ips}")

    # Renderiza el template `ips_bloqueadas.html`, pasando la lista de IPs bloqueadas.
    return render(
        request,
        "ips_bloqueadas.html",
        {"deny_ips": display_deny_ips} # Pasamos la lista de IPs que están en el JSON del usuario.
    )


"""  RUTAS PROTEGIDAS  """
@login_required # Solo usuarios autenticados pueden gestionar sus rutas protegidas
def rutas_protegidas(request):
    """
    Vista que permite a un usuario gestionar rutas específicas bajo su prefijo /<username>/
    que serán manejadas por Caddy antes de llegar a Django (ej. para un simple static_response).
    Modifica el JSON de configuración del usuario y reconstruye la configuración global de Caddy.
    """
    logger.debug(f"Usuario '{request.user.username}' accediendo a rutas protegidas.")

    # --- Obtener Configuración del Usuario ---
    try:
        # Obtiene o crea el objeto UserJSON para el usuario actual.
        user_config, created = UserJSON.objects.get_or_create(user=request.user)
        if created:
            logger.info(f"UserJSON creado automáticamente para el usuario '{request.user.username}' (no existía en rutas_protegidas).")
            # Inicializa con estructura básica si es nuevo y no tiene data.
            if not user_config.json_data:
                user_config.json_data = {
                    "apps": {"http": {"servers": {"Cloud_Guardian": {"listen": [":80"], "routes": []}}}}
                }
                user_config.save()
                logger.debug(f"Inicializado json_data para nuevo UserJSON de '{request.user.username}' en rutas_protegidas.")

        # Obtiene los datos JSON de la configuración del usuario.
        data = user_config.json_data

    except Exception as e:
        # Captura errores al obtener/crear el UserJSON.
        messages.error(request, f"Error al obtener la configuración del usuario: {e}")
        logger.error(f"Error al obtener UserJSON en rutas_protegidas para '{request.user.username}': {e}", exc_info=True)
        # Redirige a home si ocurre un error grave.
        return redirect("home")

    # --- Preparación de Datos y Extracción de Rutas Actuales ---
    # Asegura que la estructura JSON necesaria existe y obtiene la lista de rutas del usuario.
    apps = data.setdefault("apps", {})
    http = apps.setdefault("http", {})
    servers = http.setdefault("servers", {})
    cloud_guardian = servers.setdefault("Cloud_Guardian", {})
    # 'rutas' es ahora una referencia a la lista `routes` dentro de `data`.
    rutas = cloud_guardian.setdefault("routes", [])

    # Extrae solo los paths (strings) de las rutas *gestionadas por esta vista*
    # para mostrarlos en el template y para validaciones.
    # Debemos distinguir las rutas creadas por esta vista de, por ejemplo, la ruta de bloqueo de IP
    # creada por la vista `ips_bloqueadas`, para no gestionarlas desde aquí.
    rutas_actuales_paths = []
    # Iteramos sobre una copia para evitar problemas si modificamos 'rutas'.
    for r in list(rutas):
        matchers = r.get("match", [])
        # Consideramos solo rutas que:
        # 1. Tienen matchers.
        # 2. Tienen paths que empiezan con el prefijo del usuario '/<username>/'.
        # 3. NO son la ruta específica de bloqueo de IP (que gestiona `ips_bloqueadas`).
        if matchers:
            first_matcher = matchers[0]
            paths = first_matcher.get("path", [])
            path_matches_prefix = any(p.startswith(f"/{request.user.username}/") for p in paths)
            # Excluir la ruta de bloqueo de IP (tiene remote_ip matcher y handler 403)
            is_ip_block_route = ("remote_ip" in first_matcher and
                                r.get("handle", [{}])[0].get("handler") == "static_response" and
                                r.get("handle", [{}])[0].get("status_code") == 403)

            # Si cumple las condiciones (es del usuario y no es la ruta de bloqueo de IP), extrae sus paths.
            if path_matches_prefix and not is_ip_block_route:
                rutas_actuales_paths.extend(paths) # Añade todos los paths definidos en este matcher/ruta.


    # --- Procesamiento de Peticiones POST (Añadir/Eliminar Rutas) ---
    if request.method == "POST":
        # Obtiene la acción solicitada (add o delete) y la ruta del formulario.
        action = request.POST.get("action")
        ruta_add = request.POST.get("ruta_add", "").strip()
        ruta_del = request.POST.get("ruta_delete", "").strip()

        logger.info(f"Usuario '{request.user.username}' intentando acción '{action}' en rutas protegidas (Ruta add: '{ruta_add}', Ruta del: '{ruta_del}').")

        # --- Lógica para Añadir Ruta ---
        if action == "add":
            # Validaciones para añadir una ruta.
            if not ruta_add:
                messages.warning(request, "Debes escribir una ruta para añadir.")
            elif not ruta_add.startswith(f"/{request.user.username}/"):
                # Impone que las rutas del usuario deben estar bajo su prefijo /<username>/.
                messages.error(request, f"Sólo puedes proteger rutas que empiecen con '/{request.user.username}/'.")
                logger.warning(f"Usuario '{request.user.username}' intentó añadir ruta fuera de su prefijo: '{ruta_add}'")
            elif ruta_add in rutas_actuales_paths:
                # Verifica si la ruta ya existe en las que gestionamos.
                messages.info(request, f"La ruta {ruta_add} ya existe en tu configuración.")
                logger.info(f"Usuario '{request.user.username}' intentó añadir ruta duplicada: '{ruta_add}'")
            else:
                # Si la ruta es válida y no está duplicada, construye el objeto ruta de Caddy y la añade.
                nueva_ruta_usuario = {
                    "match": [{"path": [ruta_add]}], # Coincide exactamente con el path especificado.
                    # Handler de ejemplo: responde con un texto simple. Puedes cambiarlo por lo que necesites.
                    "handle": [{"handler": "static_response", "body": f"Acceso permitido a {ruta_add} (Gestionado por Cloud Guardian)"}]
                    # Ejemplo de handler para proxy:
                    # "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "localhost:puerto_de_otra_app"}]}]
                }

                # Añade la nueva ruta a la lista de rutas del usuario en el diccionario `data`.
                rutas.append(nueva_ruta_usuario) # 'rutas' es una referencia a la lista en 'data'.
                user_config.json_data = data # Asignación explícita (opcional si se modificó in-place).

                try:
                    # Guarda el objeto UserJSON actualizado en la base de datos.
                    user_config.save()
                    logger.info(f"Ruta '{ruta_add}' añadida al UserJSON de '{request.user.username}'.")

                    # Llama a la función global para reconstruir la configuración completa de Caddy
                    # (que ahora incluirá la nueva ruta del usuario) y recargar Caddy.
                    ok, msg = construir_configuracion_global()
                    # Muestra un mensaje de éxito o error basado en el resultado de la recarga de Caddy.
                    if ok:
                        messages.success(request, f"Ruta {ruta_add} añadida y recargada correctamente. {msg}")
                        logger.info(f"Recarga de Caddy exitosa tras añadir ruta protegida para '{request.user.username}'.")
                    else:
                        # Si la recarga falla, indicamos que los cambios se guardaron pero Caddy no los aplicó.
                        messages.error(request, f"Ruta {ruta_add} añadida a la base de datos, pero {msg}")
                        logger.warning(f"Fallo en la recarga de Caddy tras añadir ruta protegida para '{request.user.username}': {msg}")

                except Exception as e:
                    # Captura errores durante el proceso de guardado en la DB o la recarga de Caddy.
                    messages.error(request, f"Error al guardar la ruta protegida: {e}")
                    logger.error(f"Error al guardar UserJSON o recargar Caddy para '{request.user.username}' (rutas_protegidas add): {e}", exc_info=True)


        # --- Lógica para Eliminar Ruta ---
        elif action == "delete":
            # Validaciones para eliminar una ruta.
            if not ruta_del:
                messages.warning(request, "Debes escribir una ruta para eliminar.")
            elif ruta_del not in rutas_actuales_paths:
                # Verifica si la ruta a eliminar existe en las rutas que gestionamos.
                messages.warning(request, f"La ruta {ruta_del} no existe en tu configuración.")
                logger.info(f"Usuario '{request.user.username}' intentó eliminar ruta no existente: '{ruta_del}'")
            else:
                # Si la ruta existe, procedemos a eliminarla del JSON del usuario.
                # Debemos ser cuidadosos al eliminar: si una entrada de 'routes' tiene múltiples paths
                # en su matcher, solo queremos eliminar el path específico 'ruta_del', no toda la entrada.
                # Si la entrada solo tiene 'ruta_del' como path, eliminamos la entrada completa.
                nuevas_rutas_gestionadas = [] # Lista temporal para reconstruir las rutas del usuario.
                ruta_eliminada = False # Bandera para saber si encontramos y eliminamos la ruta.

                # Iteramos sobre una copia para poder modificar la lista original `rutas` o construir una nueva.
                for r in list(rutas):
                    matchers = r.get("match", [])
                    # Verificamos si esta ruta es una de las que gestionamos en esta vista.
                    if matchers:
                        first_matcher = matchers[0]
                        paths = first_matcher.get("path", [])
                        path_matches_prefix = any(p.startswith(f"/{request.user.username}/") for p in paths)
                        is_ip_block_route = ("remote_ip" in first_matcher and
                                            r.get("handle", [{}])[0].get("handler") == "static_response" and
                                            r.get("handle", [{}])[0].get("status_code") == 403)

                        # Si la ruta contiene el path que queremos eliminar Y es una ruta gestionada por nosotros (no la de bloqueo IP).
                        if ruta_del in paths and path_matches_prefix and not is_ip_block_route:
                            # Lógica para eliminar el path específico o la ruta completa.
                            if len(paths) > 1:
                                # Si la entrada tiene múltiples paths, solo eliminamos el path específico.
                                first_matcher["path"].remove(ruta_del)
                                nuevas_rutas_gestionadas.append(r) # Mantenemos la entrada, pero modificada.
                                ruta_eliminada = True
                                logger.debug(f"Eliminado path '{ruta_del}' de una ruta con múltiples paths para '{request.user.username}'.")
                            elif len(paths) == 1 and paths[0] == ruta_del:
                                # Si la entrada solo tiene este path, no añadimos la entrada completa a la nueva lista (la eliminamos).
                                ruta_eliminada = True
                                logger.debug(f"Eliminada ruta completa para path '{ruta_del}' de '{request.user.username}'.")
                            else:
                                # Si la ruta es gestionada por nosotros pero no contiene el path a eliminar (esto no debería pasar si ruta_del in paths), la mantenemos.
                                nuevas_rutas_gestionadas.append(r)
                        else:
                            # Si la ruta no es gestionada por nosotros o es la ruta de bloqueo IP, la mantenemos sin cambios.
                            nuevas_rutas_gestionadas.append(r)

                # Si encontramos y procesamos la ruta para eliminarla (ya sea path o entrada completa)...
                if ruta_eliminada:
                    # Reemplazamos la lista de rutas original del usuario en `data` con la lista reconstruida.
                    data["apps"]["http"]["servers"]["Cloud_Guardian"]["routes"] = nuevas_rutas_gestionadas
                    user_config.json_data = data # Asignación explícita (opcional).

                    try:
                        # Guarda el objeto UserJSON actualizado en la base de datos.
                        user_config.save()
                        logger.info(f"Ruta '{ruta_del}' eliminada del UserJSON de '{request.user.username}'.")

                        # Llama a la función global para reconstruir la configuración completa de Caddy
                        # y solicitar la recarga.
                        ok, msg = construir_configuracion_global()
                        # Muestra un mensaje de éxito o error basado en el resultado de la recarga de Caddy.
                        if ok:
                            messages.success(request, f"Ruta {ruta_del} eliminada y recargada correctamente. {msg}")
                            logger.info(f"Recarga de Caddy exitosa tras eliminar ruta protegida para '{request.user.username}'.")
                        else:
                            # Si la recarga falla, indicamos que los cambios se guardaron pero Caddy no los aplicó.
                            messages.error(request, f"Ruta {ruta_del} eliminada de la base de datos, pero {msg}")
                            logger.warning(f"Fallo en la recarga de Caddy tras eliminar ruta protegida para '{request.user.username}': {msg}")
                    except Exception as e:
                        # Captura errores durante el proceso de guardado en la DB o la recarga de Caddy.
                        messages.error(request, f"Error al guardar la eliminación de la ruta: {e}")
                        logger.error(f"Error al guardar UserJSON o recargar Caddy para '{request.user.username}' (rutas_protegidas delete): {e}", exc_info=True)

                else:
                    # Esto no debería pasar si `ruta_del in rutas_actuales_paths` fue True,
                    # pero es un mensaje de fallback por si la lógica de búsqueda/eliminación falla.
                    messages.warning(request, f"No se pudo encontrar la ruta {ruta_del} para eliminar en tu configuración.")
                    logger.warning(f"Usuario '{request.user.username}' intentó eliminar una ruta '{ruta_del}' que parecía existir pero no se encontró en la estructura JSON.")


        # Después de procesar una acción POST (add o delete), redirigimos a la misma página.
        # Esto evita que, si el usuario refresca la página después del POST, se reenvíe el formulario.
        return redirect("rutas_protegidas")

    # --- Renderizar la Página (para peticiones GET o después de POST fallido) ---
    # Prepara la lista de paths a mostrar en el template.
    # Volvemos a obtener la lista de paths por si el POST falló a mitad y queremos mostrar el estado actual de la DB.
    rutas_actuales_paths_render = []
    try:
        # Re-obtenemos la data por si UserJSON.save() falló pero el JSON en memoria se modificó antes.
        # Intentamos ser robustos leyendo el estado final de la DB.
        user_config = UserJSON.objects.get(user=request.user)
        data = user_config.json_data if user_config.json_data is not None else {}
        apps = data.get("apps", {})
        http = apps.get("http", {})
        servers = http.get("servers", {})
        cloud_guardian = servers.get("Cloud_Guardian", {})
        rutas = cloud_guardian.get("routes", [])

        # Extraemos los paths de las rutas gestionadas por esta vista, excluyendo la ruta de bloqueo IP.
        for r in rutas:
            matchers = r.get("match", [])
            if matchers:
                first_matcher = matchers[0]
                paths = first_matcher.get("path", [])
                path_matches_prefix = any(p.startswith(f"/{request.user.username}/") for p in paths)
                is_ip_block_route = ("remote_ip" in first_matcher and
                                    r.get("handle", [{}])[0].get("handler") == "static_response" and
                                    r.get("handle", [{}])[0].get("status_code") == 403)

                if path_matches_prefix and not is_ip_block_route:
                    rutas_actuales_paths_render.extend(paths)

    except Exception as e:
        logger.error(f"Error re-obteniendo rutas para renderizar en rutas_protegidas para '{request.user.username}': {e}", exc_info=True)
        messages.error(request, f"Error al cargar tus rutas protegidas: {e}")

    # Renderiza el template `rutas_protegidas.html`, pasando la lista de paths de las rutas del usuario.
    return render(request, "rutas_protegidas.html", {
        "rutas": rutas_actuales_paths_render # Pasamos la lista de strings (paths) a mostrar.
    })
    
    
    

@login_required
def destinos_externos(request):
    """
    Permite a cada usuario mapear un alias propio (p. ej. /usuario/google)
    a una URL/IP externa (reverse-proxy).
    """
    user_cfg, _ = UserJSON.objects.get_or_create(user=request.user)
    data = user_cfg.json_data

    # puntero a la lista de rutas de este user
    rutas =(data.setdefault("apps", {})
                .setdefault("http", {})
                .setdefault("servers", {})
                .setdefault("Cloud_Guardian", {})
                .setdefault("routes", []))

    # ---- carga de alias existentes ---------------------------------
    destinos: list[dict] = []       # lo que consume el template
    
    for r in rutas:
        
        # match debe ser lista; tomamos el primero
        matchers = r.get("match", [])
        if not matchers:
            continue
        
        m = matchers[0]                        # dict
        path_list = m.get("path", [])
        if not path_list:
            continue

        path_0 = path_list[0]                 # '/usuario/alias/*'
        if not path_0.startswith(f"/{request.user.username}/"):
            continue

        # handler tiene que ser lista-de-dicts y ser reverse_proxy
        handle_list = r.get("handle", [])
        if (not handle_list or
            handle_list[0].get("handler") != "reverse_proxy"):
            continue

        upstreams = handle_list[0].get("upstreams", [])
        if not upstreams or "dial" not in upstreams[0]:
            continue

        alias = path_0.split("/", 2)[2]                       
        dial  = upstreams[0]["dial"]       # ej. google.com:443
        host, _, puerto = dial.partition(":")              # “host”, “:”, “443”
        url_mostrada = ("https://" if puerto == "443" else "http://") + host

        destinos.append(
            {"alias": alias, "host": host, "puerto": puerto, "url": url_mostrada}
        )

    # ---- POST ------------------------------------------------------
    if request.method == "POST":
        action = request.POST.get("action")

        if action == "add":
            alias = request.POST.get("alias", "").strip()
            url   = request.POST.get("url",   "").strip()

            if not alias or not url:
                messages.warning(request, "Alias y URL son obligatorios.")
                return redirect("destinos_externos")

            # normaliza URL → dial  (google.com → google.com:443 , http:// → :80)
            if url.startswith("http://"):
                dial = url.removeprefix("http://").rstrip("/") + ":80"
            elif url.startswith("https://"):
                dial = url.removeprefix("https://").rstrip("/") + ":443"
            else:                                     # sin esquema → asumimos https
                dial = url.rstrip("/") + ":443"
                url  = "https://" + url.lstrip("/")

            # si ya existía, reemplazamos; si no, añadimos
            nuevo = {
                "match": [{"path": [f"/{request.user.username}/{alias}/*"]}],
                "handle": [{
                    "handler": "reverse_proxy",
                    "upstreams": [{"dial": dial}],
                    # para HTTPS remoto
                    "transport": {"protocol": "http", "tls": {}}
                }]
            }

            # elimina posible ruta anterior con el mismo alias
            rutas[:] = [
                r for r in rutas 
                if not (r.get("match", [{}])[0]
                        .get("path", [""])[0]
                    .startswith(f"/{request.user.username}/{alias}"))
            ]
            rutas.insert(0, nuevo)      
            msg_ok = f"Alias «{alias}» → {url} guardado."

        elif action == "delete":
            alias = request.POST.get("alias_del", "")
            rutas[:] = [
                r for r in rutas 
                if not (r.get("match", [{}])[0]
                        .get("path", [""])[0]
                    .startswith(f"/{request.user.username}/{alias}"))]
            msg_ok = f"Alias «{alias}» eliminado."

        else:
            messages.error(request, "Acción no reconocida.")
            return redirect("destinos_externos")

        # ---- guardamos y recargamos Caddy --------------------------
        user_cfg.json_data = data
        user_cfg.save()
        ok, msg = construir_configuracion_global()
        (messages.success if ok else messages.error)(request, f"{msg_ok} {msg}")
        return redirect("destinos_externos")

    # ---- GET -------------------------------------------------------
    return render(request, "destinos.html",
                {"destinos": destinos, "user": request.user})



# """ 🔴 API ORIGINAL (Deshabilitada) 🔴 """
    # Esta sección contiene la implementación original de varias APIs basadas en Django REST Framework.
    # Se ha deshabilitado temporalmente (usando 'if False:') porque no se utiliza actualmente
    # o para evitar conflictos y errores.
    # Si planeas usar estas APIs en el futuro, necesitarás revisar su lógica, seguridad
    # y consistencia con el sistema actual de gestión de configuración de Caddy (UserJSON en DB).


# """ 🟢🟢🟢 REGISTRO DE USUARIOS API 🟢🟢🟢"""
    # Endpoint API para registrar nuevos usuarios.
    # Utiliza un Serializador para validar y crear el usuario.
    # @api_view(['POST'])
    # def register(request):

    #     # Comentarios originales: obtenemos el nombre de usuario y la contraseña
    #     username = request.data.get("username")
    #     password = request.data.get("password")

    #     # Comentario original: creamos una instancia de UserRegisterSerializer y le pasamos los datos
    #     serializer = UserRegisterSerializer(data = request.data)

    #     # Comentario original: Verificamos si los datos enviados son válidos
    #     if serializer.is_valid():
    #         # Comentario original: Llamamos a serializer.save() para crear el usuario en la base de datos
    #         usuario = serializer.save()
    #         # Comentario original: creamos un token para el usuario
    #         Token.objects.create(user = usuario)

    #         ### INCONSISTENCIA CRÍTICA: La lógica de configuración de Caddy aquí es INCORRECTA y CONFLICTIVA.
    #         ### Este código intenta crear un JSON individual para el usuario copiando el archivo global caddy.json.
    #         ### El sistema actual (vistas clásicas y construir_configuracion_global)
    #         ### guarda la configuración por usuario en el campo json_data del modelo UserJSON en la BD,
    #         ### y construir_configuracion_global consolida TODO desde la BD en UN archivo global caddy.json.
    #         ### user_json_path = os.path.join(BASE_DIR, f"caddy_{usuario.username}.json") # Crea ruta en BASE_DIR (mala práctica)
    #         ### RIESGO: Esta ruta está en BASE_DIR, no en DEPLOY_DIR.
    #         # Comentario original: creamos la ruta para el JSON de la base de datos (Esto no es la BD, es un archivo)
    #         user_json_path_api = os.path.join(settings.BASE_DIR, f"caddy_{usuario.username}.json") # Renombrado para evitar conflicto, original: user_json_path

    #         try:
    #             # Comentario original: Cargar JSON base
    #             # ### INCONSISTENCIA CRÍTICA: Intenta cargar el JSON global (JSON_PATH) como base para el JSON individual.
    #             # ### El JSON individual debería ser una estructura vacía o por defecto para el usuario.
    #             with open(JSON_PATH, "r", encoding='utf-8') as f:
    #                  data_base = json.load(f) # Comentario original: cargamos los datos del json base en una variable

    #             # Comentario original: Escribir una copia para el usuario
    #             # ### INCONSISTENCIA: Escribe a un ARCHIVO individual, no guarda en el campo json_data del modelo UserJSON.
    #             # ### El sistema actual lee json_data de la BD, no estos archivos individuales.
    #             with open(user_json_path_api, "w", encoding="utf-8") as f: # Comentario original: creamos una copia...
    #                  json.dump(data_base, f, indent=4) # Comentario original: dumpeamos los datos...

    #             # ### INCONSISTENCIA: Aquí crea un UserJSON, pero le asigna el JSON GLOBAL (data_base) y la RUTA al archivo individual.
    #             # ### El sistema actual espera que json_data contenga SOLO la parte de configuración de Caddy para ESE USUARIO.
    #             # Comentario original: guardamos el nuevo JSON en la base de datos...
    #             UserJSON.objects.create(user = usuario, json_data = data_base, json_path = user_json_path_api)

    #             # ### INCONSISTENCIA/INEFICIENCIA: Llama a construir_configuracion_global. Esto es correcto en principio,
    #             # ### pero como el UserJSON se guardó incorrectamente (con la data global y apuntando a un archivo irrelevante),
    #             # ### la configuración de este nuevo usuario NO se reflejará correctamente en la recarga global.
    #             construir_configuracion_global()

    #             # Comentario original: si pasa algo en el proceso mandamos un msg y un codigo de estado
    #             # ### NOTA: El bloque except actual captura *cualquier* Exception durante el manejo de archivos/DB/recarga,
    #             # ### lo cual puede ocultar la causa raíz real del error. Un manejo de excepciones más granular sería mejor.
    #         except Exception as e:
    #              logger.error(f"Error en API de registro al crear archivo/UserJSON para '{username}': {e}", exc_info=True)
    #              # ### RIESGO/MEJORA: Considerar eliminar el usuario y token si falla la creación del UserJSON/archivo,
    #              # ### para evitar usuarios incompletos en la DB.
    #              # ### Mejora: Devolver el error específico si es posible.
    #              return Response({"error": f"Error interno al configurar Caddy para el usuario: {e}"}, status = status.HTTP_500_INTERNAL_SERVER_ERROR)

    #         # Comentario original: si todo va bien devolvemos esto
    #         return Response({"message": "Usuario registrado y configuración inicial creada"}, status = status.HTTP_201_CREATED)

    #     # Comentario original: si la validación del serializador falla, devolvemos los errores
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




# """ 🔴🔴🔴 CLASE Y FUNCION PARA ELIMINAR USUARIOS DE LA BASE DE DATOS (API) 🔴🔴🔴 """
    # Endpoint API para eliminar usuarios usando una "masterkey".
    # ### RIESGO DE SEGURIDAD CRÍTICO: El uso de una "masterkey" hardcodeada y compartida es MUY inseguro.
    # ### La eliminación de usuarios debería estar protegida por autenticación fuerte y permisos de administrador (ej. @staff_member_required si fuera vista clásica, o DRF permissions como IsAdminUser para APIs).
    # # Eliminar usuarios (API)
    # class UserDelete(APIView): # Comentario original: definimos la clase para eliminar usuario
    #     # No tiene decorators de autenticación/permisos, lo que lo hace accesible públicamente si la URL está mapeada.
    #     def post(self, request): # Comentario original: definimos la funcion que recibe la peticion mediante el metodo post

    #         # Comentario original: Elimina un usuario por su nombre de usuario si indican la masterkey necesaria
    #         username = request.data.get("username") # Comentario original: obtenemos el username
    #         key = request.data.get("masterkey") # Comentario original: obtenemos la masterkey
    #         masterkey = "delete" # Comentario original: aqui tenemos el valor de la masterkey
    #         ### RIESGO DE SEGURIDAD: Masterkey hardcodeada.

    #         if key == masterkey: # Comentario original: si la key es igual a la masterkey dale accesi

    #             try:
    #                 # Comentario original: obtenemos el usuario de la base de datos
    #                 user = User.objects.get(username = username)
    #                 # ### MEJORA: Añadir comprobación para no permitir eliminar superusuarios con esta API.
    #                 # Comentario original: lo borramos de la base de datos
    #                 user.delete() # Asumimos que on_delete=CASCADE en UserJSON elimina la config de la BD.

    #                 # ### INCONSISTENCIA/RIESGO: Intenta eliminar el archivo JSON individual del usuario.
    #                 # ### Como se mencionó antes, este archivo no forma parte del sistema de configuración activo (que usa json_data en BD).
    #                 # ### Si el path no existe o Django no tiene permisos, dará un error.
    #                 # Comentario original: ruta al fichero del usuario a eliminar
    #                 user_json_path_api = os.path.join(settings.BASE_DIR, f"caddy_{username}.json") # Renombrado
    #                 if os.path.exists(user_json_path_api):
    #                      try:
    #                         os.remove(user_json_path_api)
    #                         logger.info(f"Archivo JSON individual '{user_json_path_api}' eliminado para usuario '{username}' via UserDelete API.")
    #                      except Exception as file_e:
    #                          logger.error(f"Error al eliminar archivo JSON '{user_json_path_api}' para usuario '{username}': {file_e}", exc_info=True)
    #                          # Decide si quieres que la operación falle si el archivo no se puede eliminar.
    #                          # messages.warning(None, f"Usuario eliminado, pero no se pudo eliminar el archivo de configuración JSON.") # Mensaje global si aplica

    #                 # ### MEJORA: Después de eliminar al usuario y su config (de la BD), RECARGAR Caddy
    #                 # ### para que la configuración global deje de incluir sus rutas.
    #                 # ### Esto FALTA en el código original de esta API.
    #                 # construir_configuracion_global() # <-- Esta llamada falta aquí pero es NECESARIA.
    #                 # ok, msg = construir_configuracion_global() # Deberías llamar a esto y reportar el resultado.

    #                 # Comentario original: si todo sale bien devolvemos esto
    #                 # ### MEJORA: El status 202 Accepted es correcto, pero el mensaje podría ser más claro si la recarga falla.
    #                 return Response({"message":f"Usuario: {username} eliminado correctamente"}, status = status.HTTP_202_ACCEPTED)


    #             except User.DoesNotExist:
    #                 # Comentario original: si no existe devolvemos esto
    #                 return Response({"error":f"El usuario: {username} no existe"}, status = status.HTTP_404_NOT_FOUND)

    #             except Exception as e:
    #                 # ### MEJORA: Capturar excepciones más específicas si es posible.
    #                 # ### MEJORA: Registrar el error en los logs del servidor.
    #                 logger.error(f"Error inesperado en UserDelete API para usuario '{username}': {e}", exc_info=True)
    #                 return Response({"error":f"Ocurrió un error al intentar eliminar al usuario '{username}': {e}"}, status = status.HTTP_500_INTERNAL_SERVER_ERROR)


    #         else:
    #             # Comentario original: si fallas con la masterkey te aparecera esto
    #             # ### MEJORA: Usar status 401 Unauthorized o 403 Forbidden en lugar de 203 Non-Authoritative Information.
    #             # ### MEJORA: Registrar intentos de acceso fallidos a la API.
    #             logger.warning(f"Intento fallido de eliminar usuario con masterkey incorrecta para usuario: '{username}'.")
    #             return Response({"error":"Contraseña maestra incorrecta, no puedes eliminar usuarios"}, status = status.HTTP_401_UNAUTHORIZED) # Mejor usar 401 o 403



# """ LISTA DE USUARIOS PARA TESTEAR COSAS (API) """
    # Endpoint API para listar usuarios, JSONs y Tokens.
    # ### RIESGO DE SEGURIDAD CRÍTICO: Expone DATOS SENSIBLES (incluyendo TOKENS DE AUTENTICACIÓN)
    # ### sin ninguna autenticación o permiso. Cualquier persona que acceda a esta URL podrá ver esta información.
    # #  Listar usuarios (API)
    # class listarUsers(APIView):
    #     # No tiene decorators de autenticación/permisos, lo que lo hace accesible públicamente.
    #     def get(self, request):
    #         # Comentario original: usuarios de la base de datos
    #         users = list(User.objects.values()) # Lista diccionarios de usuarios
    #         # Comentario original: jsons (Parece referirse a UserJSONs)
    #         jsons = list(UserJSON.objects.values()) # Lista diccionarios de UserJSONs (incluye json_data)
    #         # Comentario original: tokens
    #         tokens = list(Token.objects.values()) # Lista diccionarios de Tokens (¡incluye las claves de los tokens!)

    #         ### RIESGO DE SEGURIDAD CRÍTICO: Exponer tokens así es muy peligroso.
    #         logger.error("API listarUsers accedida, exponiendo datos de usuario y tokens sin autenticación.")

    #         # Comentario original: devolvemos los datos
    #         return Response({"Usuarios": users, "JSONs": jsons, "Tokens": tokens}, status = status.HTTP_200_OK) # Mejor usar 200 OK




# """ 👋👋👋 FUNCIONES PARA INICIO DE SESION Y CIERRE DE SESION API 👋👋👋 """
    # Endpoints API para autenticación con Token.
    # # Login API
    # @api_view(['POST']) # Comentario original: solo acepta peticiones POST.
    # def login(request):  # Comentario original: Define la función login_view (Nombre conflictivo con la vista clásica)

    #     # Comentario original: obtenemos el username y password del cuerpo de la request (usando request.data de DRF)
    #     username = request.data.get("username")
    #     password = request.data.get("password")

    #     # Comentario original: verificamos que las credenciales son correctas usando authenticate
    #     user = authenticate(username = username, password = password)

    #     # Comentario original: si el usuario existe
    #     if user:
    #         # Comentario original: si el usuario no tiene token en la bbdd crea uno para el
    #         # get_or_create devuelve una tupla (objeto, creado), solo necesitamos el objeto token.
    #         token, _ = Token.objects.get_or_create(user = user)

    #         try:
    #             # Comentario original: obtenemos el JSON de la base de datos del user autenticado
    #             # ### INCONSISTENCIA/INEFICIENCIA: Llama a construir_configuracion_global() en CADA login exitoso.
    #             # ### Esto recarga Caddy cada vez que alguien inicia sesión, lo cual es innecesario e ineficiente.
    #             # ### Caddy solo necesita recargarse cuando la configuración CAMBIA (al añadir/eliminar IPs, rutas, o modificar el JSON).
    #             user_config = UserJSON.objects.get(user = user)

    #             # ### INEFICIENCIA GRAVE: Recargar Caddy en cada login. Eliminar esta llamada.
    #             # construir_configuracion_global() # <-- Eliminar o comentar esta línea si solo se llama desde aquí.

    #             # ### RIESGO POTENCIAL/MEJORA: Devolver la configuración Caddy completa del usuario en la respuesta de login
    #             # ### puede exponer más detalles de configuración interna de Caddy de lo deseado al cliente.
    #             # Comentario original: devolvemos el token y la configuracion caddy del usuario
    #             return Response({"token": token.key, "caddy_config": user_config.json_data}, status=status.HTTP_200_OK) # Mejor usar status.HTTP_200_OK

    #         except UserJSON.DoesNotExist:
    #             logger.error(f"UserJSON no encontrado para usuario '{user.username}' durante el login API.")
    #             # ### MEJORA: Si no hay UserJSON, podrías crearlo aquí con una config inicial en lugar de devolver 404.
    #             return Response({"error": f"No se encontró configuración para el usuario {user.username}"}, status=status.HTTP_404_NOT_FOUND)
    #         except Exception as e:
    #              # ### MEJORA: Capturar otros errores durante la obtención del UserJSON.
    #              logger.error(f"Error inesperado obteniendo UserJSON para '{user.username}' durante login API: {e}", exc_info=True)
    #              return Response({"error": f"Error interno al obtener configuración de usuario."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    #     # Comentario original: si hay algun error devuelve un mensaje y un error 400
    #     # ### MEJORA: Usar status 401 Unauthorized en lugar de 400 Bad Request para credenciales incorrectas.
    #     logger.warning(f"Intento de login API fallido para usuario: '{username}'.")
    #     return Response({"error": "Credenciales incorrectas"}, status=status.HTTP_401_UNAUTHORIZED) # Mejor usar 401 Unauthorized





# # Logout API
    # @api_view(['POST']) # Comentario original: Solo permite peticiones POST
    # # Usa TokenAuthentication para identificar al usuario por el token en el header
    # @authentication_classes([TokenAuthentication])
    # # Requiere que el usuario esté autenticado para ejecutar esta vista
    # @permission_classes([IsAuthenticated])
    # def logout(request): # Comentario original: Define la funcion para cerrar sesion de usuario eliminando el token

    #     # DRF TokenAuthentication ya valida el token y setea request.user si es válido.
    #     # No es necesario obtener el token manualmente del header si solo vas a borrar el del usuario autenticado.

    #     # Comentario original: obtener el token del header (Este código es redundante si se usa TokenAuthentication)
    #     # token_header = request.headers.get('Authorization')
    #     # if not token_header:
    #     #    return Response({'error': 'No se proporcionó token en la solicitud'}, status = status.HTTP_400_BAD_REQUEST)
    #     # token_key = token_header.replace("Token ", "").strip()

    #     try:
    #         # Elimina el token asociado al usuario autenticado (request.user).
    #         # Esto es más seguro que intentar borrar un token por su clave obtenida manualmente del header.
    #         # request.user.auth_token.delete() # Esta es la forma recomendada si el modelo Token es el predeterminado
    #         # O si usas el modelo Token directamente y tienes Token.objects.get_or_create en login:
    #         Token.objects.filter(user=request.user).delete()
    #         logger.info(f"Logout API exitoso para usuario '{request.user.username}'. Token(s) eliminado(s).")
    #         # Comentario original: si se ha eliminado mandamos un msg y un estado 200
    #         return Response({'message': 'Logout exitoso, token(s) eliminado(s).'}, status=status.HTTP_200_OK)

    #     except Token.DoesNotExist:
    #         # Este caso es poco probable si @authentication_classes([TokenAuthentication]) pasó,
    #         # ya que significa que request.user fue autenticado por un token que ahora no existe.
    #         # Podría ocurrir si el token se elimina entre la autenticación y la ejecución de la vista.
    #         logger.warning(f"Intento de logout API de usuario '{request.user.username}' pero no se encontró su token.")
    #         # Comentario original: si se ha pasado un token pero no es valido o ya a expirado.
    #         return Response({'error': 'Token asociado no encontrado o ya inválido.'}, status=status.HTTP_400_BAD_REQUEST) # o 401/403



# """ 🖥️🖥️🖥️ FUNCION PARA LEER O MODIFICAR EL JSON PARA VER O MODIFICAR SU CONFIGURACION (API) 🖥️🖥️🖥️ """
    # Endpoint API para que un usuario autenticado lea o actualice su configuración JSON de Caddy (campo json_data en UserJSON).
    # # Leer o modificar configuración caddy.json (API)
    # @api_view(['GET', 'PUT']) # Comentario original: configura la vista para manejar los métodos HTTP GET y PUT
    # # Requiere autenticación por Token
    # @authentication_classes([TokenAuthentication]) # Comentario original: es para autenticar el token automaticamente
    # # Requiere que el usuario esté autenticado para GET y PUT.
    # # Si quisieras GET público y PUT autenticado, usarías permission_classes([IsAuthenticatedOrReadOnly]).
    # @permission_classes([IsAuthenticated]) # Comentario original: solo los autenticados pueden modificar, los demas solo lectura (Esto aplica a ambos métodos GET/PUT aquí)
    # def caddy_config_view(request): # Comentario original: definimos la funcion que va a leer o modificar el .json

    #     # JSON_PATH = '/etc/caddy/caddy.json'  # Ruta dentro del contenedor (Comentado, bien)
    #     # Comentario original: el usuario es automáticamente autenticado por DRF
    #     user = request.user

    #     try:
    #         # Comentario original: obtenemos los datos del JSON del user autenticado de la base de datos
    #         user_config = UserJSON.objects.get(user = user)

    #     except UserJSON.DoesNotExist:
    #         logger.error(f"UserJSON no encontrado para usuario '{user.username}' en caddy_config_view.")
    #         # ### MEJORA: Si no existe, podrías crearlo aquí con una config inicial en lugar de 404.
    #         # Comentario original: si no existe devuelve esto
    #         return Response({"error": "No se encontró configuración para este usuario."}, status=status.HTTP_404_NOT_FOUND)

    #     # Comentario original: Esta es la funcion para el GET
    #     if request.method == 'GET':
    #         # Comentario original: devuelve simplemente los datos de dentro del user_config
    #         return Response(user_config.json_data, status=status.HTTP_200_OK) # Añadido status

    #     # Comentario original: Esta es la funcion para el PUT
    #     elif request.method == 'PUT':
    #         # Comentario original: metemos la nueva configuracion en una variable, esta nueva configuracion la hemos obtenido de la peticion
    #         new_config = request.data # request.data ya es el contenido parseado (ej. JSON) del cuerpo.

    #         # Comentario original: comprobamos que los datos que nos han mandado son en formato diccionario
    #         if not isinstance(new_config, dict):
    #             # Comentario original: en caso de que no sea en formato diccionario devolvemos un error 400
    #             logger.warning(f"Usuario '{user.username}' envió formato inválido (no dict) a caddy_config_view PUT.")
    #             return Response({'error': 'El cuerpo de la solicitud debe ser un objeto JSON (diccionario).'}, status = status.HTTP_400_BAD_REQUEST)

    #         # TODO (CRÍTICO): Añadir validación ESTRICTA aquí del contenido de new_config.
    #         # Actualmente, un usuario puede enviar CUALQUIER JSON válido (incluso uno con claves "admin", "listen",
    #         # o modificar rutas que no sean suyas si conoce la estructura interna) y esto se guardará en su json_data.
    #         # Esto podría permitirles inyectar configuración maliciosa o romper la estructura esperada por construir_configuracion_global.
    #         # Deberías validar que 'new_config' solo contiene las partes que un usuario puede modificar (ej. la lista de 'routes' bajo 'Cloud_Guardian').
    #         # Ejemplo de validación básica de estructura (ya en la vista clásica, se copia aquí):
    #         if not isinstance(new_config, dict) or "apps" not in new_config or "http" not in new_config.get("apps", {}) or \
    #            "servers" not in new_config.get("apps", {}).get("http", {}) or \
    #            "Cloud_Guardian" not in new_config.get("apps", {}).get("http", {}).get("servers", {}):
    #              logger.warning(f"Usuario '{user.username}' envió JSON con estructura básica inválida a caddy_config_view PUT.")
    #              return Response({"error": "Estructura JSON de configuración inválida. La estructura básica esperada no se encontró."}, status = status.HTTP_400_BAD_REQUEST)
    #         # TODO: Validación más profunda sobre qué se puede modificar dentro de la estructura.


    #         # Comentario original: le pasamos la nueva configuracion a nuestra configuracion (en memoria)
    #         user_config.json_data = new_config
    #         # Comentario original: lo guardamos en la base de datos
    #         try:
    #             user_config.save()
    #             logger.info(f"Configuración de UserJSON guardada en DB para usuario '{user.username}' via API PUT.")
    #         except Exception as save_e:
    #              logger.error(f"Error guardando UserJSON para '{user.username}' via API PUT: {save_e}", exc_info=True)
    #              return Response({"error": "Error al guardar la configuración en la base de datos."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    #         # Llama a la función global para reconstruir la configuración de Caddy y recargarla.
    #         # Esto usa la data recién guardada de la BD.
    #         logger.info(f"Llamando a construir_configuracion_global tras PUT API de config por '{user.username}'.")
    #         ok, msg = construir_configuracion_global()

    #         # Comentario original: si todo va bien devolvemos esto
    #         # ### MEJORA: Incluir el resultado de la recarga de Caddy en el mensaje de respuesta.
    #         response_message = f"Configuración actualizada correctamente. {msg}" if ok else f"Configuración actualizada en la base de datos, pero {msg}"
    #         status_code = status.HTTP_200_OK if ok else status.HTTP_500_INTERNAL_SERVER_ERROR # Decide el status basado en la recarga

    #         if not ok:
    #             logger.warning(f"Recarga de Caddy fallida tras PUT API de config por '{user.username}': {msg}")
    #             messages.error(request, msg) # Opcional: usar el sistema de mensajes si aplica en el contexto de la API

    #         return Response({"message": response_message}, status=status_code)


        
# """ CLASES PARA AÑADIR Y ELIMINAR IPS PERMITIDAS Y BLOQUEADAS (APIs) """
    # Endpoints API para gestionar IPs bloqueadas/permitidas.
    # ### RIESGO DE SEGURIDAD CRÍTICO: Estas APIs MODIFICAN DIRECTAMENTE el archivo GLOBAL caddy.json.
    # ### Esto es INCONSISTENTE con el diseño que guarda la config por usuario en la BD (UserJSON)
    # ### y MUY PELIGROSO si no tienen autenticación/permisos (que no los tienen en el código proporcionado).
    # ### Cualquier persona con acceso a la URL de esta API podría modificar el archivo de configuración global de Caddy.
    # # Añadir IPs (API)
    # class AddIPs(APIView): # Comentario original: Esta es la clase para añadir ips al json
    #     # NO tiene decorators de autenticación/permisos. ¡RIESGO!
    #     def post(self, request): # Comentario original: funcion que recibe una peticion mediante el metodo post

    #         # Comentario original: obtenemos las ips a permitir y a bloquear de la peticion
    #         new_ips_allow = request.data.get("allow-ips")
    #         new_ips_deny = request.data.get("deny-ips")

    #         # ### RIESGO CRÍTICO / INCONSISTENCIA: Intenta modificar DIRECTAMENTE el archivo JSON GLOBAL.
    #         # ### El diseño actual guarda la config por usuario en UserJSON en la BD.
    #         # ### Esto también es propenso a race conditions si múltiples peticiones acceden al archivo al mismo tiempo.
    #         try:
    #             # Comentario original: abrimos nuestro caddy.json (EL GLOBAL)
    #             with open(JSON_PATH, 'r+', encoding="utf-8") as f:
    #                  data = json.load(f) # Comentario original: cargamos todos los datos

    #             # ### INCONSISTENCIA / RIESGO: Accede a una estructura de seguridad en el JSON GLOBAL.
    #             # ### El bloqueo de IP por usuario en el diseño de vistas clásicas se hace DENTRO de la ruta específica de ese usuario.
    #             # ### Aquí parece que intenta modificar una lista global de IPs permitidas/denegadas.
    #             # Comentario original: lista de ips permitidas/denegadas
    #             ips_allow = data.get("apps", {}).get("http", {}).get("security", {}).get("remote_ip", {}).setdefault("allow", []) # Usando .get con defaults para seguridad
    #             ips_deny = data.get("apps", {}).get("http", {}).get("security", {}).get("remote_ip", {}).setdefault("deny", []) # Usando .get con defaults para seguridad

    #             # ### MEJORA: Validar que new_ips_allow/deny son IPs/CIDR válidos antes de añadir.
    #             # ### MEJORA: Manejar listas de IPs en lugar de solo una IP por petición.
    #             if new_ips_allow:
    #                  if _ip_valida(new_ips_allow): # Validar formato
    #                     if new_ips_allow not in ips_allow: # Evitar duplicados
    #                          ips_allow.append(new_ips_allow)
    #                          logger.info(f"API AddIPs: Añadida IP '{new_ips_allow}' a lista global ALLOW.")
    #                     else: logger.info(f"API AddIPs: IP '{new_ips_allow}' ya en lista global ALLOW.")
    #                  else: logger.warning(f"API AddIPs: Intentó añadir IP inválida '{new_ips_allow}' a ALLOW.")


    #             if new_ips_deny:
    #                  if _ip_valida(new_ips_deny): # Validar formato
    #                     if new_ips_deny not in ips_deny: # Evitar duplicados
    #                          ips_deny.append(new_ips_deny)
    #                          logger.info(f"API AddIPs: Añadida IP '{new_ips_deny}' a lista global DENY.")
    #                     else: logger.info(f"API AddIPs: IP '{new_ips_deny}' ya en lista global DENY.")
    #                  else: logger.warning(f"API AddIPs: Intentó añadir IP inválida '{new_ips_deny}' a DENY.")


    #             # Comentario original: Sobreescribir el archivo JSON con los nuevos datos
    #             # ### RIESGO DE RACE CONDITION: Múltiples peticiones POST simultáneas podrían interferir aquí.
    #             f.seek(0)
    #             json.dump(data, f, indent=4) # Comentario original: dumpeamos los datos
    #             f.truncate() # Comentario original: Ajustar el tamaño del archivo

    #             # ### MEJORA: Llamar a construir_configuracion_global() y recargar Caddy DESPUÉS de modificar el archivo.
    #             # ### Esta API FALTA la llamada a la recarga, por lo que Caddy NO aplicará los cambios hasta que se recargue externamente.
    #             # ok, msg = construir_configuracion_global() # <-- Esta llamada falta aquí pero es NECESARIA.
    #             # logger.info(f"Resultado de recarga de Caddy tras AddIPs API: {msg}")
    #             # response_msg = f"IPs añadidas. {msg}" if ok else f"IPs añadidas al archivo, pero {msg}"


    #             # Comentario original: si todo sale bien devolvemos esto
    #             # ### MEJORA: El status 201 Created es correcto si se crearon entradas, pero quizás 200 OK si solo se modificó.
    #             # ### MEJORA: El mensaje de respuesta debería indicar si la recarga de Caddy tuvo éxito.
    #             return Response({"message": "IPs añadidas correctamente"}, status=status.HTTP_201_CREATED)


    #         # Comentario original: si hay algun error en el proceso devolvemos esto
    #         # ### MEJORA: Capturar excepciones más específicas y registrarlas.
    #         # ### RIESGO: Except bare 'except:' captura TODOS los errores, incluyendo errores de tipografía o lógicos, haciendo la depuración difícil.
    #         except Exception as e:
    #             logger.error(f"Error inesperado en AddIPs API: {e}", exc_info=True)
    #             return Response({"error": "Error al añadir IPs"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



# #  Eliminar IPs (API)
    # class DeleteIPs(APIView): # Comentario original: clase para eliminar ips
    #     # NO tiene decorators de autenticación/permisos. ¡RIESGO!
    #     def post(self, request): # Comentario original: funcion que recibe la peticion del cliente mediante el metodo post

    #         # Comentario original: obtenemos las ips a eliminar
    #         delete_ips_allow = request.data.get("allow-ips")
    #         delete_ips_deny = request.data.get("deny-ips")

    #         # ### RIESGO CRÍTICO / INCONSISTENCIA / RACE CONDITION: Modifica DIRECTAMENTE el archivo JSON GLOBAL.
    #         try:
    #             # Comentario original: abrimos nuestro json (EL GLOBAL)
    #             with open(JSON_PATH, 'r+', encoding="utf-8") as f:
    #                 data = json.load(f) # Comentario original: cargamos los datos

    #             # ### INCONSISTENCIA / RIESGO: Accede a una estructura de seguridad en el JSON GLOBAL.
    #             # Comentario original: lista de ips permitidas/denegadas, usando setdefault para crear si no existen
    #             ips_allow = data.get("apps", {}).get("http", {}).get("security", {}).get("remote_ip", {}).setdefault("allow", [])
    #             ips_deny = data.get("apps", {}).get("http", {}).get("security", {}).get("remote_ip", {}).setdefault("deny", [])

    #             # Bandera para saber si realmente eliminamos algo
    #             removed_count = 0

    #             # Comentario original: logica para eliminar de la lista allow
    #             if delete_ips_allow:
    #                  if _ip_valida(delete_ips_allow): # Validar formato a eliminar (opcional pero bueno)
    #                     if delete_ips_allow in ips_allow:
    #                          ips_allow.remove(delete_ips_allow)
    #                          removed_count += 1
    #                          logger.info(f"API DeleteIPs: Eliminada IP '{delete_ips_allow}' de lista global ALLOW.")
    #                     else: logger.info(f"API DeleteIPs: IP '{delete_ips_allow}' no encontrada en lista global ALLOW.")
    #                  else: logger.warning(f"API DeleteIPs: Intentó eliminar IP inválida '{delete_ips_allow}' de ALLOW.")

    #             # Comentario original: logica para eliminar de la lista deny
    #             if delete_ips_deny:
    #                  if _ip_valida(delete_ips_deny): # Validar formato a eliminar (opcional pero bueno)
    #                     if delete_ips_deny in ips_deny:
    #                          ips_deny.remove(delete_ips_deny)
    #                          removed_count += 1
    #                          logger.info(f"API DeleteIPs: Eliminada IP '{delete_ips_deny}' de lista global DENY.")
    #                     else: logger.info(f"API DeleteIPs: IP '{delete_ips_deny}' no encontrada en lista global DENY.")
    #                  else: logger.warning(f"API DeleteIPs: Intentó eliminar IP inválida '{delete_ips_deny}' de DENY.")


    #             # Comentario original: Sobreescribir el archivo JSON con los nuevos datos
    #             # ### RIESGO DE RACE CONDITION.
    #             f.seek(0)
    #             json.dump(data, f, indent=4) # Comentario original: dumpeamos los datos
    #             f.truncate() # Comentario original: Ajustar el tamaño del archivo

    #             # ### MEJORA: Llamar a construir_configuracion_global() y recargar Caddy DESPUÉS de modificar el archivo.
    #             # ### Esta API FALTA la llamada a la recarga.
    #             # ok, msg = construir_configuracion_global() # <-- Esta llamada falta aquí pero es NECESARIA.
    #             # logger.info(f"Resultado de recarga de Caddy tras DeleteIPs API: {msg}")
    #             # response_msg = f"Operación completada. {msg}" if ok else f"Operación guardada en archivo, pero {msg}"


    #             # Comentario original: si todo a ido bien devolvemos esto (mensaje que incluye ambas eliminaciones)
    #             # ### MEJORA: Verificar si realmente se eliminó algo antes de decir que todo fue correcto.
    #             # ### El mensaje de respuesta original es confuso y no usa las variables.
    #             # ### El status 201 Created no es apropiado para una eliminación; 200 OK o 204 No Content es mejor.
    #             if removed_count > 0:
    #                 # ### MEJORA: Incluir el resultado de la recarga de Caddy.
    #                 return Response({"message": f"Operación completada. IPs eliminadas: ALLOW={delete_ips_allow if delete_ips_allow in ips_allow else 'no encontrada'} DENY={delete_ips_deny if delete_ips_deny in ips_deny else 'no encontrada'}"}, status=status.HTTP_200_OK) # Mejor 200 OK
    #             else:
    #                 # Comentario original: si alguna de las ips que se pasan no existen en el caddy.json devolvemos este msg y status
    #                 # ### MEJORA: El status 400 Bad Request podría estar bien, o 404 Not Found si esperabas que existieran.
    #                 # ### El mensaje original es un poco confuso.
    #                 logger.warning(f"API DeleteIPs: Intentó eliminar IPs que no estaban en las listas globales: ALLOW='{delete_ips_allow}', DENY='{delete_ips_deny}'.")
    #                 return Response({"message":"Alguna(s) de la(s) IP(s) especificadas no se encontraron en las listas.", "ips_not_found": {"allow": delete_ips_allow if delete_ips_allow not in ips_allow else None, "deny": delete_ips_deny if delete_ips_deny not in ips_deny else None}}, status = status.HTTP_404_NOT_FOUND) # Mejor 404 Not Found

    #         # Comentario original: por si ha habido algún error inesperado
    #         # ### MEJORA: Capturar excepciones más específicas y registrarlas.
    #         # ### RIESGO: Except bare 'except:' oculta la causa raíz.
    #         except Exception as e:
    #             logger.error(f"Error inesperado en DeleteIPs API: {e}", exc_info=True)
    #             # Comentario original: si ocurre otro error en el proceso devolvemos esto
    #             return Response({"message": f"Ha habido un error en el proceso: {e}"}, status = status.HTTP_500_INTERNAL_SERVER_ERROR)


            
# """ 🛤️🛤️🛤️ CLASES Y FUNCIONES PARA AÑADIR Y ELIMINAR RUTAS PROTEGIDAS (APIs) 🛤️🛤️🛤️ """
    # Endpoints API para gestionar rutas protegidas.
    # ### RIESGO DE SEGURIDAD CRÍTICO: Estas APIs MODIFICAN DIRECTAMENTE el archivo GLOBAL caddy.json.
    # ### No tienen autenticación/permisos en el código proporcionado.
    # #  Añadir rutas protegidas (API)
    # class AddRoutes(APIView): # Comentario original: clase para añadir rutas protegidas
    #     # NO tiene decorators de autenticación/permisos. ¡RIESGO!
    #     def post(self, request):

    #         # Comentario original: ruta que queremos agregar
    #         new_path = request.data.get("path")
    #         # ### INCONSISTENCIA / RIESGO: Obtener TODOS los usuarios y sus CONTRASEÑAS (¡planas!) de la DB aquí.
    #         # ### Esto es INSEGURO y probablemente innecesario/incorrecto para la lógica de añadir UNA ruta.
    #         # ### La parte 'basic: {"users": users}' en el handler de Caddy DEBERÍA usarse para autenticar UN usuario PUNTUAL
    #         # ### o leer de un fichero, no cargar TODA la base de datos de usuarios y contraseñas en la configuración.
    #         # Comentario original: usuarios de la base de datos
    #         # users_db_dict = {user.username: user.password for user in User.objects.all()} # <-- RIESGO CRÍTICO: Exponer contraseñas. Renombrado para evitar conflicto
    #         # Además, esta lógica parece estar mezclando la gestión de UNA ruta con la inclusión de TODOS los usuarios para basic auth.
    #         # Esto hace que cada ruta añadida por esta API intente aplicar basic auth con TODOS los usuarios del sistema.

    #         # Comentario original: validacion basica si no se añade ruta
    #         if not new_path:
    #             return Response({"error": "Añade alguna ruta"}, status=status.HTTP_400_BAD_REQUEST)

    #         # ### RIESGO CRÍTICO / INCONSISTENCIA / RACE CONDITION: Modifica DIRECTAMENTE el archivo JSON GLOBAL.
    #         # ### El diseño actual gestiona rutas por usuario en UserJSON en la BD.
    #         try:
    #             # Comentario original: abrimos nuestro caddy.json (EL GLOBAL)
    #             with open(JSON_PATH, "r+", encoding = "utf-8") as f:
    #                 data = json.load(f) # Comentario original: cargamos los datos

    #                 # Comentario original: Acceder a la lista de rutas en Caddy (DEL GLOBAL)
    #                 routes = data["apps"]["http"]["servers"]["Cloud_Guardian"].setdefault("routes", [])

    #                 # Comentario original: Comprobar si la ruta ya existe en las rutas GLOBALES
    #                 # ### INCONSISTENCIA: Debería verificar si existe en las rutas *del usuario actual* si se alinea con el otro diseño.
    #                 # ### Si esta API pretende añadir rutas GLOBALES, la validación está bien, pero el uso es distinto.
    #                 for route in routes:
    #                      # ### MEJORA: Usar .get para acceder a 'match' y 'path' de forma segura.
    #                      for match in route.get("match", []):
    #                          if "path" in match and new_path in match["path"]:
    #                              # Comentario original: si la ruta ya existe
    #                              logger.warning(f"API AddRoutes: Intento de añadir ruta global duplicada '{new_path}'.")
    #                              return Response({"error": f"La ruta '{new_path}' ya existe"}, status=status.HTTP_400_BAD_REQUEST)

    #                 # Comentario original: Crear la nueva ruta protegida (GLOBAL)
    #                 # ### RIESGO / INCONSISTENCIA: Este handler aplica rate_limit, basic auth con TODOS los usuarios (¡obteniendo contraseñas!),
    #                 # ### y un static_response. Esto no es coherente con la gestión de rutas por usuario en la BD.
    #                 # ### La parte de basic auth con `users_db_dict` es particularmente peligrosa.
    #                 new_route = {
    #                     "match": [{"path": [new_path]}],
    #                     "handle": [
    #                         {
    #                             "handler": "rate_limit",
    #                             "rate_limit": {
    #                                 "requests": 5,  # Máximo de 5 requests por minuto
    #                                 "window": "1m"
    #                             }
    #                         },
    #                         {
    #                             "handler": "authenticate",
    #                             "basic": {
    #                                 # ### RIESGO CRÍTICO: NO HAGAS ESTO EN PRODUCCIÓN. Expone todas las contraseñas.
    #                                 # ### Esto intenta configurar basic auth con todos los usuarios de la BD.
    #                                 "users": {user.username: user.password for user in User.objects.all()} # <-- PELIGROSO
    #                             }
    #                         },
    #                         {
    #                             "handler": "static_response",
    #                             "body": f"Acceso permitido a {new_path}"
    #                         }
    #                     ]
    #                 }

    #                 # Comentario original: Agregar la nueva ruta al JSON GLOBAL
    #                 routes.append(new_route)

    #                 # Comentario original: Guardar cambios en el archivo JSON (GLOBAL)
    #                 # ### RIESGO DE RACE CONDITION.
    #                 f.seek(0)
    #                 json.dump(data, f, indent = 4)
    #                 f.truncate()

    #                 # ### MEJORA: Llamar a construir_configuracion_global() y recargar Caddy DESPUÉS de modificar el archivo.
    #                 # ### Esta API FALTA la llamada a la recarga.
    #                 # ok, msg = construir_configuracion_global() # <-- Esta llamada falta aquí pero es NECESARIA.
    #                 # logger.info(f"Resultado de recarga de Caddy tras AddRoutes API: {msg}")
    #                 # response_msg = f"Ruta segura '{new_path}' añadida. {msg}" if ok else f"Ruta añadida al archivo, pero {msg}"

    #                 # Comentario original: si todo está correcto devolvemos un msg y un status
    #                 # ### MEJORA: El status 201 Created es correcto.
    #                 # ### MEJORA: El mensaje de respuesta debería indicar si la recarga de Caddy tuvo éxito.
    #                 return Response({"message": f"Ruta segura '{new_path}' añadida correctamente"}, status=status.HTTP_201_CREATED)

    #         # Comentario original: por si ha ocurrido algún error inesperado
    #         # ### MEJORA: Capturar excepciones más específicas y registrarlas.
    #         # ### RIESGO: Except bare 'except:' oculta la causa raíz.
    #         except Exception as e:
    #             logger.error(f"Error inesperado en AddRoutes API: {e}", exc_info=True)
    #             return Response({"error": f"Ha ocurrido algún error en el proceso: {e}"}, status = status.HTTP_500_INTERNAL_SERVER_ERROR)

    # #  Eliminar rutas protegidas (API)
    # class DeleteRoutes(APIView): # Comentario original: clase para eliminar rutas protegidas

    #     # NO tiene decorators de autenticación/permisos. ¡RIESGO!
    #     def post(self, request): # Comentario original: definimos la funcion que recibe la peticion mediante el metodo post

    #         # Comentario original: recibe el path de la peticion
    #         delete_path = request.data.get("path")

    #         # Comentario original: validacion basica si no se añade ruta
    #         if not delete_path:
    #             return Response({"error":"No has añadido ninguna ruta, porfavor añade una ruta."}, status = status.HTTP_400_BAD_REQUEST)

    #         # ### RIESGO CRÍTICO / INCONSISTENCIA / RACE CONDITION: Modifica DIRECTAMENTE el archivo JSON GLOBAL.
    #         try:
    #             # Comentario original: abrimos nuestro json (EL GLOBAL)
    #             with open(JSON_PATH, "r+", encoding = "utf-8") as f:
    #                 data = json.load(f) # Comentario original: cargamos los datos

    #                 # Comentario original: Acceder a la lista de rutas en Caddy (DEL GLOBAL), usando get con default
    #                 routes = data["apps"]["http"]["servers"]["Cloud_Guardian"].get("routes", [])

    #                 # Comentario original: Lógica para crear una nueva lista excluyendo la ruta a eliminar.
    #                 # Esta lógica intenta eliminar cualquier ruta (GLOBAL) que contenga el 'delete_path' en CUALQUIERA de sus matchers/paths.
    #                 # Esto podría eliminar rutas no deseadas si un path corto está contenido en un path más largo.
    #                 # ### MEJORA: La lógica de eliminación de rutas en la vista clásica de templates (rutas_protegidas) es más robusta
    #                 # ### al intentar eliminar solo el path específico o la entrada si es la única.
    #                 new_routes = [route for route in routes if all(delete_path not in match.get("path", []) for match in route.get("match", []))] # Comentario original de la lógica

    #                 # Comentario original: comprobamos si el número de rutas cambió
    #                 if len(new_routes) == len(routes):
    #                      # Comentario original: si el número es el mismo, la ruta no existía
    #                      logger.warning(f"API DeleteRoutes: Intento de eliminar ruta global no existente '{delete_path}'.")
    #                      return Response({"error": f"La ruta '{delete_path}' no existe"}, status=status.HTTP_404_NOT_FOUND) # Mejor 404 Not Found

    #                 # Comentario original: actualizamos la lista de rutas en el JSON GLOBAL
    #                 data["apps"]["http"]["servers"]["Cloud_Guardian"]["routes"] = new_routes

    #                 # Comentario original: Guardar cambios en el archivo JSON (GLOBAL)
    #                 # ### RIESGO DE RACE CONDITION.
    #                 f.seek(0)
    #                 json.dump(data, f, indent=4)
    #                 f.truncate()

    #                 # ### MEJORA: Llamar a construir_configuracion_global() y recargar Caddy DESPUÉS de modificar el archivo.
    #                 # ### Esta API FALTA la llamada a la recarga.
    #                 # ok, msg = construir_configuracion_global() # <-- Esta llamada falta aquí pero es NECESARIA.
    #                 # logger.info(f"Resultado de recarga de Caddy tras DeleteRoutes API: {msg}")
    #                 # response_msg = f"Ruta '{delete_path}' eliminada. {msg}" if ok else f"Ruta eliminada del archivo, pero {msg}"

    #                 # Comentario original: si todo está correcto devolvemos un msg y un status
    #                 # ### MEJORA: El status 200 OK es correcto.
    #                 # ### MEJORA: El mensaje de respuesta debería indicar si la recarga de Caddy tuvo éxito.
    #                 return Response({"message": f"Ruta '{delete_path}' eliminada correctamente"}, status = status.HTTP_200_OK)


    #         # Comentario original: por si ha habido algún error inesperado
    #         # ### MEJORA: Capturar excepciones más específicas y registrarlas.
    #         # ### RIESGO: Except bare 'except:' oculta la causa raíz.
    #         except Exception as e:
    #             logger.error(f"Error inesperado en DeleteRoutes API: {e}", exc_info=True)
    #             # Comentario original: por si ha habido algún error inesperado
    #             return Response({"message": f"Ha habido un error en el proceso: {e}"}, status = status.HTTP_500_INTERNAL_SERVER_ERROR)


# --- Fin del Bloque de Código de la API Original (Deshabilitado) ---