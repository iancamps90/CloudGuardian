
from __future__ import annotations


# ── estándar ───────────────────────────────────────────────────
import ipaddress
import os
import json
import requests
import re  
from typing import Dict, List, Tuple, Any 
import logging # Importamos el módulo de logging para rastrear eventos y errores
from urllib.parse import urlparse
from .models import UserJSON

""" DJANGO IMPORTS """
# Importaciones estándar de Django para vistas basadas en función, autenticación, etc.
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required, user_passes_test # Decorador para requerir login
from django.contrib.admin.views.decorators import staff_member_required # Decorador para requerir staff/superuser
# from django.utils.decorators import method_decorator # (No usado en vistas basadas en función aquí)
from django.contrib import messages # Sistema de mensajes de Django
from django.views.decorators.csrf import csrf_exempt # (Usado si deshabilitas CSRF, úsalo con precaución)
from django.utils.text import slugify
from django.db import IntegrityError

from django.conf import settings # Importamos settings para configuraciones específicas del entorno


# --- Importaciones de funciones de utilidad ---
from .utils import (
    construir_configuracion_global, 
    get_public_ip_address, 
    dial_permitido, 
    _is_valid_domain,    
    _is_valid_target_url, 
    CaddyAPIError
)

from .forms import IpBlockingForm 

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

# Importamos tus modelos y serializadores personalizados
# from .serializers import UserRegisterSerializer # 


server_ip = settings.SERVER_PUBLIC_IP


# --- Configuración del Logger ---
# Configura el manejo de logging en tu settings.py para ver estos mensajes 
logger = logging.getLogger(__name__)



""" 🔵 VISTAS CLÁSICAS PARA TEMPLATES 🔵 """


""" FUNCIONES DE SUPERUSUARIO: PARA ELIMINAR USUARIOS """
@login_required
@user_passes_test(lambda u: u.is_superuser, login_url='/') # Solo superusuarios
def eliminar_usuario(request):
    if request.method == 'POST':
        action = request.POST.get('action')
        username_to_delete = request.POST.get('username')

        if action == 'delete' and username_to_delete:
            try:
                user_to_delete = User.objects.get(username=username_to_delete)
                if user_to_delete.is_superuser and user_to_delete != request.user:
                    messages.error(request, f"No puedes eliminar al superusuario '{username_to_delete}'.")
                elif user_to_delete == request.user:
                    messages.error(request, "No puedes eliminar tu propia cuenta.")
                else:
                    user_to_delete.delete()
                    messages.success(request, f"Usuario '{username_to_delete}' eliminado correctamente.")
            except User.DoesNotExist:
                messages.error(request, f"El usuario '{username_to_delete}' no existe.")
            except IntegrityError:
                messages.error(request, f"No se pudo eliminar al usuario '{username_to_delete}' debido a datos relacionados. Intenta eliminarlo manualmente si es necesario.")
            except Exception as e:
                messages.error(request, f"Error al eliminar usuario: {e}")
        else:
            messages.error(request, "Acción no válida o usuario no especificado.")

        return redirect('eliminar_usuario')

    users = User.objects.all().order_by('username')
    return render(request, 'eliminar_usuario.html', {'users': users})


"""  HOME (DASHBOARD)  """
def home_view(request):
    """
    Panel de control principal.
    Muestra un resumen de la configuración del usuario con conteos.
    """
    logger.debug(f"Usuario '{request.user.username}' accediendo a la página de inicio (home_view).")

    # Obtener la IP pública del servidor para mostrarla en el panel
    server_ip = get_public_ip_address() 

    if request.user.is_authenticated:
        try:
            user_cfg_obj, created = UserJSON.objects.get_or_create(user=request.user)
            
            if created:
                logger.info(f"UserJSON creado automáticamente para '{request.user.username}' (en home_view).")
                # Inicializar la estructura base de Caddy para un nuevo UserJSON
                # Asegura que las claves existan con los puertos de settings.py
                user_cfg_obj.json_data = {
                    "apps": {
                        "http": {
                            "servers": {
                                settings.SERVIDOR_CADDY: {
                                    "listen": [f":{settings.CADDY_HTTP_PORT}", f":{settings.CADDY_HTTPS_PORT}"],
                                    "routes": []
                                }
                            }
                        }
                    }
                }
                user_cfg_obj.save()
            else:
                # Asegurarse de que la estructura básica de Caddy exista si UserJSON ya existía pero no estaba completo
                # Esto maneja casos de UserJSONs antiguos o malformados.
                # No guardamos si no hay cambios, solo aseguramos la estructura para evitar errores al accederla.
                user_cfg_obj.json_data.setdefault("apps", {}) \
                                    .setdefault("http", {}) \
                                    .setdefault("servers", {}) \
                                    .setdefault(settings.SERVIDOR_CADDY, {"listen": [f":{settings.CADDY_HTTP_PORT}", f":{settings.CADDY_HTTPS_PORT}"], "routes": []})
                # No es necesario user_cfg_obj.save() aquí a menos que realmente se modifique json_data
                # ya que solo estamos "asegurando" la existencia de claves, no reescribiendo la estructura completa.

            # La variable `data` ahora es `user_cfg_obj.json_data`
            user_caddy_data = user_cfg_obj.json_data

            # --- Obtener Conteos para las Tarjetas Resumen analizando las rutas de Caddy ---
            domain_proxy_count = 0
            ip_block_count = 0
            external_destination_count = 0

            # Accede a las rutas de Caddy del usuario de forma segura
            routes = user_caddy_data.get("apps", {}).get("http", {}).get("servers", {}).get(settings.SERVIDOR_CADDY, {}).get("routes", [])

            # Itera sobre las rutas para contar los diferentes tipos
            for route in routes:
                matchers = route.get("match", [])
                handle = route.get("handle", [])

                # Para que una ruta sea considerada "del usuario", debe empezar con su nombre de usuario
                is_user_route = False
                for matcher_group in matchers:
                    paths = matcher_group.get("path", [])
                    if any(p.startswith(f"/{request.user.username}/") for p in paths):
                        is_user_route = True
                        break # Salir del bucle de matchers si ya encontramos una ruta de usuario

                if is_user_route:
                    # Contar bloqueos de IP
                    if any("remote_ip" in m and handle and handle[0].get("handler") == "static_response" and handle[0].get("status_code") == 403 and m["remote_ip"].get("ranges") for m in matchers):
                        ip_block_count += 1
                    # Contar destinos externos (reverse proxy)
                    elif any(h.get("handler") == "reverse_proxy" and h.get("upstreams") for h in handle):
                        external_destination_count += 1
                    # Contar otros tipos de rutas protegidas o dominios proxy generales
                    
                    # Esto es una categoría "catch-all" para rutas de usuario no clasificadas s
                    else:
                        domain_proxy_count += 1 

            context = {
                'user': request.user,
                'server_ip': server_ip,
                'domain_proxy_count': domain_proxy_count,
                'ip_block_count': ip_block_count,
                'external_destination_count': external_destination_count,
                'is_superuser': request.user.is_superuser, 
            }
            logger.debug(f"[{request.user.username}] Renderizando home.html con conteos: IP={ip_block_count}, Destinos={external_destination_count}, Dominios={domain_proxy_count}.")
            return render(request, 'home.html', context)
        
        except Exception as e:
            logger.exception(f"Error CRÍTICO en home_view para '{request.user.username}'.")
            messages.error(request, f"Error al cargar el panel de control: {e}")
            
            # En caso de error, todavía renderiza la página con la IP y el usuario, pero con un mensaje de error.
            return render(request, 'home.html', {'user': request.user, 'server_ip': server_ip, 'error_message': "No se pudieron cargar todos los datos."})


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
            # Si el usuario existe y la contraseña es correcta, iniciar la sesión.
            auth_login(request, user)
            messages.success(request, f"¡Bienvenido, {username}!")
            logger.info(f"Usuario '{username}' ha iniciado sesión correctamente.")
            
            # Redirigir al usuario. Primero intenta a una URL 'next', si no, a 'home'.
            next_url = request.GET.get('next', 'home')
            return redirect(next_url)
        else:
            # Si la autenticación falla (usuario o contraseña incorrectos).
            messages.error(request, "Usuario o contraseña incorrectos.")
            logger.warning(f"Intento de inicio de sesión fallido para usuario: '{username}'.")
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
            user = User.objects.create_user(username=username, password=password1)
            logger.info(f"Nuevo usuario de Django creado: '{username}'.")
            
            # Estructura base de Caddy para el nuevo usuario
            default_config_json = {
                "apps": {
                    "http": {
                        "servers": {
                            settings.SERVIDOR_CADDY: {
                                "listen": [f":{settings.CADDY_HTTP_PORT}", f":{settings.CADDY_HTTPS_PORT}"],
                                "routes": []
                            }
                        }
                    }
                },
                
            }
            
            # Crear el UserJSON asociado al usuario
            UserJSON.objects.create(user=user, json_data=default_config_json)
            logger.info(f"UserJSON inicializado para '{username}'.")
            
            # Iniciar sesión al usuario recién registrado
            auth_login(request, user)
            messages.success(request, f"¡Bienvenido, {username}! Tu cuenta ha sido creada.")
            return redirect("home")
        
        except Exception as e:
            logger.exception(f"Error crítico durante el registro de '{username}'.") 
            messages.error(request, "Ocurrió un error inesperado durante el registro. Por favor, intenta de nuevo.")

            # Intento de limpiar el usuario si se creó pero UserJSON falló
            if 'user' in locals() and user.pk:
                try:
                    user.delete()
                    logger.warning(f"Usuario '{username}' creado, pero eliminado debido a un fallo en UserJSON.")
                    
                except Exception as delete_e:
                    logger.error(f"Error al limpiar usuario '{username}' tras fallo de registro: {delete_e}", exc_info=True)
                    messages.error(request, f"Fallo en la creación de la cuenta para '{username}' y en la limpieza de datos. Contacta al administrador.")
                    
            return render(request, "register.html", {"username": username})

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
            with open(settings.JSON_PATH, "r", encoding="utf-8") as f: # Usa settings.JSON_PATH
                global_config = json.load(f)
            config_json = json.dumps(global_config, indent=4)
            logger.debug(f"Leído caddy.json global de {settings.JSON_PATH}.")
            
        except FileNotFoundError:
            messages.warning(request, f"El archivo de configuración global '{settings.JSON_PATH}' no se encontró. Se mostrará un JSON vacío.")
            config_json = "{}"
            logger.warning(f"Archivo caddy.json global no encontrado para superusuario '{request.user.username}'.")
            
        except json.JSONDecodeError:
            messages.error(request, f"El archivo de configuración global '{settings.JSON_PATH}' contiene JSON inválido. Corrige manualmente.")
            config_json = "" # Dejar vacío para indicar un error grave
            json_error = True
            logger.error(f"El archivo {settings.JSON_PATH} contiene JSON inválido para superusuario '{request.user.username}'.")
            
        except Exception as e:
            messages.error(request, f"Error inesperado al leer el caddy.json global: {e}")
            logger.exception(f"Error inesperado al leer caddy.json global para superusuario '{request.user.username}'.")
            return redirect("home") # Redirigir a home si hay un error grave al cargar la página

        # Si la petición es POST, el superusuario ha enviado una configuración editada.
        if request.method == "POST":
            # Obtiene el texto del JSON enviado en el formulario.
            new_config_str = request.POST.get("config", "").strip()
            logger.info(f"Superusuario '{request.user.username}' intentando actualizar la configuración global.")

            try:
                # Intenta parsear el texto recibido como JSON.
                data = json.loads(new_config_str)

                # Si el JSON es válido, lo guarda SOBREESCRIBIENDO el archivo caddy.json global.
                # Django necesita permisos de ESCRITURA en JSON_PATH.
                with open(settings.JSON_PATH, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
                logger.info(f"Archivo caddy.json global actualizado en {settings.JSON_PATH}.")

                # Llama a la función para reconstruir la configuración global (que leerá el archivo recién guardado)
                # y solicitar la recarga a Caddy.
                # La función `construir_configuracion_global` ya maneja la recarga por API y devuelve su resultado.
                ok, msg = construir_configuracion_global(iniciado_por=f"Superuser config update por {request.user.username}") # Añade iniciado_por
                    
                # Muestra un mensaje de éxito o error basado en el resultado de la recarga de Caddy.
                if ok:
                    messages.success(request, f"Configuración global actualizada y recargada correctamente. {msg}")
                    logger.info(f"Recarga de Caddy exitosa tras actualización global por superusuario '{request.user.username}'.")
                        
                else:
                    # Si la recarga falla, mostramos el mensaje de error de Caddy/requests.
                    messages.error(request, f"Configuración global actualizada, pero {msg}")
                    logger.warning(f"Fallo en la recarga de Caddy tras actualización global por superusuario '{request.user.username}': {msg}")
                
                config_json = json.dumps(data, indent=4) # Mostrar la config recién guardada/procesada
                json_error = False # Si llegamos aquí, el JSON es válido



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
                
            # Después de POST, renderizar la misma página con el resultado
            return render(request, "configuracion.html", {
                "config": config_json,
                "is_superuser": True,
                "json_is_invalid": json_error
            })
            
            

    # --- Lógica para Usuarios Normales ---
    else: # Si el usuario NO es superusuario.
        logger.debug(f"Usuario normal '{request.user.username}' accediendo a su configuración.")
        
        # Obtener o crear el UserJSON del usuario
        try:
            user_cfg_obj, created = UserJSON.objects.get_or_create(user=request.user)
            if created or not user_cfg_obj.json_data: # Si es nuevo o json_data está vacío/None
                if created:
                    logger.info(f"UserJSON creado automáticamente para '{request.user.username}'.")
                else:
                    logger.warning(f"UserJSON de '{request.user.username}' sin datos, inicializando.")
                
                # Inicializar con la estructura Caddy de usuario
                user_cfg_obj.json_data = {
                    "apps": {
                        "http": {
                            "servers": {
                                settings.SERVIDOR_CADDY: {
                                    "listen": [f":{settings.CADDY_HTTP_PORT}", f":{settings.CADDY_HTTPS_PORT}"],
                                    "routes": []
                                }
                            }
                        }
                    }
                }
                user_cfg_obj.save()
                logger.debug(f"Inicializado json_data para '{request.user.username}'.")
            
            # Obtener el JSON actual del usuario para mostrarlo
            config_json = json.dumps(user_cfg_obj.json_data, indent=4)

        except Exception as e:
            messages.error(request, f"Error al obtener la configuración del usuario: {e}")
            logger.exception(f"Error al obtener/crear UserJSON para '{request.user.username}'.")
            
            return redirect("home") # Redirigir a home si no se puede cargar la configuración

        # Si es una petición POST (usuario normal intentando guardar)
        if request.method == "POST":
            new_config_str = request.POST.get("config", "").strip()
            logger.info(f"Usuario '{request.user.username}' intentando actualizar su configuración JSON.")

            try:
                new_user_data = json.loads(new_config_str) # Intenta parsear el JSON

                # --- VALIDACIÓN CRÍTICA PARA USUARIOS NORMALES ---
                # Un usuario normal NO debería poder modificar cualquier parte del JSON de Caddy.
                # Aquí se valida que solo se puedan modificar las rutas (routes) y que estas rutas
                # contengan el prefijo del nombre de usuario.
                
                # Asegurar la estructura básica
                if not (isinstance(new_user_data, dict) and
                        new_user_data.get("apps", {}).get("http", {}).get("servers", {}).get(settings.SERVIDOR_CADDY)):
                    raise ValueError("Estructura JSON básica inválida o incompleta.")

                # Extraer las rutas del nuevo JSON
                new_routes = new_user_data["apps"]["http"]["servers"][settings.SERVIDOR_CADDY].get("routes", [])
                if not isinstance(new_routes, list):
                    raise ValueError("Las rutas deben ser una lista.")

                # Validar que todas las rutas nuevas pertenecen al usuario
                for route in new_routes:
                    matchers = route.get("match", [])
                    is_valid_route_for_user = False
                    
                    for matcher_group in matchers:
                        paths = matcher_group.get("path", [])
                        if any(p.startswith(f"/{request.user.username}/") for p in paths):
                            is_valid_route_for_user = True
                            break
                    if not is_valid_route_for_user:
                        raise ValueError(f"La ruta '{route}' no es válida o no pertenece al usuario '{request.user.username}'.")
                
                # Si todas las validaciones pasan, actualizar solo la sección de rutas
                user_cfg_obj.json_data["apps"]["http"]["servers"][settings.SERVIDOR_CADDY]["routes"] = new_routes
                user_cfg_obj.save()
                logger.info(f"Configuración JSON guardada en BD para '{request.user.username}'.")
                
                # Después de guardar en la DB, reconstruir y recargar Caddy
                ok, msg = construir_configuracion_global(iniciado_por=f"User config update por {request.user.username}")
                if ok:
                    messages.success(request, f"Tu configuración ha sido actualizada y Caddy recargado correctamente. {msg}")
                    logger.info(f"Recarga de Caddy exitosa tras actualización de '{request.user.username}'.")
                else:
                    messages.error(request, f"Tu configuración fue guardada, pero Caddy no pudo recargarse: {msg}")
                    logger.warning(f"Fallo en la recarga de Caddy tras actualización de '{request.user.username}': {msg}")

                return redirect("configuracion") # Redirigir para evitar reenvío de formulario

            except json.JSONDecodeError:
                messages.error(request, "Formato JSON inválido enviado. Por favor, revisa la sintaxis.")
                logger.warning(f"Usuario '{request.user.username}' envió JSON inválido para su configuración.")
                json_error = True
                config_json = new_config_str # Mostrar el JSON inválido para que lo corrija
                
            except ValueError as ve: # Errores de validación personalizada
                messages.error(request, f"Error de validación en la configuración: {ve}")
                logger.warning(f"Usuario '{request.user.username}' envió configuración JSON inválida: {ve}")
                json_error= True
                config_json = new_config_str
                
            except Exception as e:
                messages.error(request, f"Ocurrió un error inesperado al procesar tu configuración: {e}")
                logger.exception(f"Error al procesar configuración de '{request.user.username}'.")
                json_error = True
                config_json = new_config_str # Mostrar el último JSON intentado

            # Si hay un error, se renderiza de nuevo la página con el JSON y el error.
            return render(request, "configuracion.html", {
                "config": config_json,
                "is_superuser": False,
                "json_is_invalid": json_error
            })

    # Renderizar el template para peticiones GET (o POST con errores)
    return render(request, "configuracion.html", {
        "config": config_json,
        "is_superuser": is_superuser,
        "json_is_invalid": json_error
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

    user_cfg_obj = None # Inicializa para el bloque try/except
    try:
        user_cfg_obj, created = UserJSON.objects.get_or_create(user=request.user)
        if created or not user_cfg_obj.json_data:
            if created:
                logger.info(f"UserJSON creado automáticamente para '{request.user.username}' en ips_bloqueadas.")
            else:
                logger.warning(f"UserJSON de '{request.user.username}' sin datos, inicializando en ips_bloqueadas.")
            
            # Inicializar con la estructura completa de Caddy para el usuario
            user_cfg_obj.json_data = {
                "apps": {
                    "http": {
                        "servers": {
                            settings.SERVIDOR_CADDY: {
                                "listen": [f":{settings.CADDY_HTTP_PORT}", f":{settings.CADDY_HTTPS_PORT}"],
                                "routes": []
                            }
                        }
                    }
                }
            }
            user_cfg_obj.save()
            logger.debug(f"Inicializado json_data para '{request.user.username}' en ips_bloqueadas.")

    except Exception as e:
        messages.error(request, f"Error al cargar la configuración del usuario: {e}")
        logger.exception(f"Error al obtener/crear UserJSON para '{request.user.username}' en ips_bloqueadas.")
        return redirect("home") # Redirigir a home en caso de error crítico

    # Obtener una referencia mutable a las rutas del usuario
    user_routes = user_cfg_obj.json_data \
                    .setdefault("apps", {}) \
                    .setdefault("http", {}) \
                    .setdefault("servers", {}) \
                    .setdefault(settings.SERVIDOR_CADDY, {}) \
                    .setdefault("routes", [])
                    
    # Encontrar la ruta de bloqueo de IP existente para este usuario
    ip_block_route = next((
        r for r in user_routes
        if any(p.startswith(f"/{request.user.username}/") for m in r.get("match", []) for p in m.get("path", []))
        and any("remote_ip" in m for m in r.get("match", []))
        and r.get("handle", [{}])[0].get("handler") == "static_response"
        and r.get("handle", [{}])[0].get("status_code") == 403
    ), None)

    current_blocked_ips = []
    if ip_block_route:
        # Extraer las IPs bloqueadas existentes
        current_blocked_ips = [
            ip for m in ip_block_route.get("match", [])
            for ip in m.get("remote_ip", {}).get("ranges", [])
            # La validación ya no es necesaria aquí si asumimos que las IPs en DB son válidas
            # o si el validador de formulario garantiza que solo se guarden válidas.
            # if _ip_valida(ip) # Si la función _ip_valida no está definida globalmente, elimínala
        ]
    logger.debug(f"IPs bloqueadas existentes para '{request.user.username}': {current_blocked_ips}")

    # --- Manejar peticiones POST (Añadir/Eliminar IPs) ---
    if request.method == "POST":
        form = IpBlockingForm(request.POST) # ¡Instancia el formulario con los datos POST!
        logger.debug(f"Petición POST recibida en ips_bloqueadas. Datos POST: {request.POST}")
        
        if form.is_valid():
            logger.debug("Formulario de IP bloqueada es válido.")
            ip_input = form.cleaned_data['ip_address']
            action = form.cleaned_data['action'] # Obtener la acción del campo oculto

            logger.info(f"Usuario '{request.user.username}' intentando acción '{action}' en IPs bloqueadas con valor: '{ip_input}'.")

            if action == "add":
                if ip_input in current_blocked_ips:
                    messages.info(request, f"La IP/CIDR {ip_input} ya está bloqueada.")
                    logger.info(f"Intento de añadir IP duplicada '{ip_input}' por usuario '{request.user.username}'.")
                else:
                    current_blocked_ips.append(ip_input)
                    messages.success(request, f"IP/CIDR {ip_input} añadida a la lista de bloqueo.")
                    logger.info(f"Usuario '{request.user.username}' añadió IP/CIDR a la lista de bloqueo: '{ip_input}'.")
                    
            elif action == "delete":
                if ip_input in current_blocked_ips:
                    current_blocked_ips.remove(ip_input)
                    messages.success(request, f"IP/CIDR {ip_input} eliminada de la lista de bloqueo.")
                    logger.info(f"Usuario '{request.user.username}' eliminó IP/CIDR de la lista de bloqueo: '{ip_input}'.")
                else:
                    messages.warning(request, f"La IP/CIDR {ip_input} no se encontró en la lista de bloqueo.")
                    logger.warning(f"Intento de eliminar IP no existente '{ip_input}' por usuario '{request.user.username}'.")
            else:
                messages.error(request, "Acción solicitada inválida.")
                logger.warning(f"Usuario '{request.user.username}' envió acción inválida '{action}'.")
        
            # Lógica para actualizar el JSON en la DB y recargar Caddy
            # Actualizar/eliminar la ruta de bloqueo de IP de Caddy basándose en la lista `current_blocked_ips` modificada
            if current_blocked_ips: # Si hay IPs para bloquear, asegurarse de que la ruta exista y esté actualizada
                new_ip_block_route_definition = {
                    "match": [{
                        "path": [f"/{request.user.username}/*"],
                        "remote_ip": {"ranges": sorted(list(set(current_blocked_ips)))} # Asegura unicidad y ordena
                    }],
                    "handle": [{
                        "handler": "static_response",
                        "status_code": 403,
                        "body": "IP bloqueada por Cloud Guardian"
                    }]
                }
                # Buscar y actualizar o añadir la ruta de bloqueo de IP
                found_route_idx = -1
                for i, r in enumerate(user_routes):
                    if any(p.startswith(f"/{request.user.username}/") for m in r.get("match", []) for p in m.get("path", [])) \
                       and any("remote_ip" in m for m in r.get("match", [])):
                        found_route_idx = i
                        break
                
                if found_route_idx != -1: 
                    user_routes[found_route_idx] = new_ip_block_route_definition
                    logger.debug(f"Ruta de bloqueo de IP existente actualizada para '{request.user.username}'.")
                else: 
                    user_routes.insert(0, new_ip_block_route_definition) # Añadir al principio para precedencia
                    logger.debug(f"Nueva ruta de bloqueo de IP creada para '{request.user.username}'.")
            
            elif ip_block_route: # Si no hay IPs para bloquear y la ruta existía, eliminarla
                user_routes.remove(ip_block_route)
                logger.debug(f"Ruta de bloqueo de IP eliminada para '{request.user.username}' (no hay IPs que bloquear).")

            # Guardar el UserJSON actualizado
            try:
                user_cfg_obj.json_data = user_cfg_obj.json_data # Asegurar que los cambios están listos para guardar
                user_cfg_obj.save()
                logger.info(f"Configuración de IPs bloqueadas guardada en DB para el usuario '{request.user.username}'.")

                # Disparar la recarga de Caddy
                ok, msg = construir_configuracion_global(iniciado_por=f"User IP block update by {request.user.username}")
                (messages.success if ok else messages.error)(
                    request,
                    f"Operación completada. {msg}" if ok else f"Cambios guardados en la base de datos, pero {msg}"
                )
                logger.info(f"Resultado de recarga de Caddy después de la actualización de IPs bloqueadas para '{request.user.username}': {msg}")

            except Exception as e:
                messages.error(request, f"Error al guardar la configuración o recargar Caddy: {e}")
                logger.exception(f"Error al guardar UserJSON o recargar Caddy para '{request.user.username}' (ips_bloqueadas POST).")
            
            return redirect("ips_bloqueadas") # Redirigir para evitar reenvío de formulario
        else: # Formulario no válido
            logger.warning(f"Formulario de IP bloqueada NO válido. Errores: {form.errors}")
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"Error en el campo '{field}': {error}")
            # Si el formulario no es válido, no redirigimos, mostramos la página con los errores
            # para que el usuario pueda corregirlos.
    else: # GET request
        form = IpBlockingForm() # Crea un formulario vacío para el GET

    # Renderizar la página (para peticiones GET o después del procesamiento POST si el formulario es inválido)
    display_ips = sorted(list(set(current_blocked_ips))) # Asegura unicidad y ordena para mostrar
    logger.debug(f"Renderizando página de IPs bloqueadas para '{request.user.username}' con IPs: {display_ips}")

    context = {
        'form': form,
        'deny_ips': display_ips, # Cambié el nombre de 'ips_bloqueadas' a 'deny_ips' para que coincida con tu template
    }
    return render(request, "ips_bloqueadas.html", context) 



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
    logger.debug(f"Usuario '{request.user.username}' accediendo a destinos externos.")

    # 1. Obtenemos (o creamos) el JSON de este usuario
    try:
        user_cfg_obj, created = UserJSON.objects.get_or_create(user=request.user)
        if created or not user_cfg_obj.json_data:
            if created:
                logger.info(f"UserJSON creado automáticamente para '{request.user.username}' en destinos_externos.")
            else:
                logger.warning(f"UserJSON de '{request.user.username}' sin datos, inicializando en destinos_externos.")

            # Inicializar con la estructura completa de Caddy para el usuario
            user_cfg_obj.json_data = {
                "apps": {
                    "http": {
                        "servers": {
                            settings.SERVIDOR_CADDY: {
                                "listen": [f":{settings.CADDY_HTTP_PORT}", f":{settings.CADDY_HTTPS_PORT}"],
                                "routes": []
                            }
                        }
                    }
                }
            }
            user_cfg_obj.save()
            logger.debug(f"Inicializado json_data para '{request.user.username}' en destinos_externos.")

        # Asegurarse de que la ruta exista y sea mutable
        user_routes = user_cfg_obj.json_data \
                            .setdefault("apps", {}) \
                            .setdefault("http", {}) \
                            .setdefault("servers", {}) \
                            .setdefault(settings.SERVIDOR_CADDY, {}) \
                            .setdefault("routes", [])

    except Exception as e:
        messages.error(request, f"Error al cargar la configuración del usuario: {e}")
        logger.exception(f"Error al obtener/crear UserJSON para '{request.user.username}' en destinos_externos.")
        return redirect("home") # Redirigir a home en caso de error crítico

    # 2. Re-construimos la lista 'destinos' para el template en cada renderizado (GET y POST)
    # Esto asegura que la lista 'destinos' siempre refleje el estado actual del user_cfg_obj
    destinos_para_template = []
    for r in user_routes:
        # Identificamos las rutas de reverse_proxy que pertenecen a este usuario
        matchers = r.get("match", [])
        if not matchers:
            continue
        
        path_matcher = next((m for m in matchers if "path" in m), None)
        if not path_matcher:
            continue
        
        path_list = path_matcher.get("path", [])
        if not path_list:
            continue
        
        full_path_caddy = path_list[0] # Ej: '/usuario/alias/*'
        
        # Debe empezar con el prefijo del usuario y ser un proxy
        if not full_path_caddy.startswith(f"/{request.user.username}/"):
            continue

        handle = r.get("handle", [])
        if not handle or handle[0].get("handler") != "reverse_proxy":
            continue
        
        upstreams = handle[0].get("upstreams", [])
        if not upstreams or "dial" not in upstreams[0]:
            continue

        alias_caddy = full_path_caddy.split(f"/{request.user.username}/", 1)[1].rstrip("/*")
        target_url_caddy = upstreams[0]["dial"]
        
        # Intentar separar host y puerto para la visualización 
        host_display = target_url_caddy
        port_display = ""
        
        # Parsear la URL de destino para host y puerto si es posible
        parsed_url = None
        try:
            # Primero intentar como una URL completa
            parsed_url = urlparse(target_url_caddy)
            if parsed_url.hostname:
                host_display = parsed_url.hostname
                if parsed_url.port:
                    port_display = str(parsed_url.port)
                else: # Si no hay puerto, intentar default
                    if parsed_url.scheme == 'http':
                        port_display = '80'
                    elif parsed_url.scheme == 'https':
                        port_display = '443'
        except ValueError:
            pass # No es una URL bien formada, intentar como IP:Puerto

        if not parsed_url or not parsed_url.hostname: # Si no se parseó como URL o no tiene hostname, intentar como IP:Puerto
            if ":" in target_url_caddy:
                temp_parts = target_url_caddy.rsplit(":", 1)
                if len(temp_parts) == 2 and temp_parts[1].isdigit():
                    try:
                        ipaddress.ip_address(temp_parts[0]) 
                        host_display = temp_parts[0]
                        port_display = temp_parts[1]
                    except ValueError:
                        pass 
            
        destinos_para_template.append({
            "alias": alias_caddy,
            "target_url": target_url_caddy,
            "host": host_display,
            "port": port_display
        })

    #  Procesamiento de Peticiones POST 
    if request.method == "POST":
        action = request.POST.get("action")
        alias_input = request.POST.get("alias", "").strip()
        target_url_input = request.POST.get("url", "").strip() 

        logger.info(f"Usuario '{request.user.username}' intentando acción '{action}' en destinos externos (Alias: '{alias_input}', Destino: '{target_url_input}').")


        if action == "add":
            if not alias_input or not target_url_input:
                messages.warning(request, "Debes introducir tanto un alias como una URL/IP de destino.")
            elif not re.match(r"^[a-zA-Z0-9_-]+$", alias_input): # Validación básica del alias
                messages.error(request, "El alias solo puede contener letras, números, guiones y guiones bajos.")
            elif not _is_valid_target_url(target_url_input):
                messages.error(request, f"La URL/IP de destino '{target_url_input}' no es un formato válido. Ejemplos válidos: http://ejemplo.com, 192.168.1.1:8080, api.dominio.es")
            else:
                # Validar si el alias ya existe en las rutas de destino externo del usuario
                alias_already_exists = any(d.get("alias") == alias_input for d in destinos_para_template)
                
                if alias_already_exists:
                    messages.info(request, f"El alias '{alias_input}' ya existe. Si quieres cambiar su destino, elimínalo primero y luego añádelo de nuevo.")
                    logger.info(f"Usuario '{request.user.username}' intentó añadir alias duplicado: '{alias_input}'")
                else:
                    # Crear la nueva ruta de Caddy para el reverse_proxy
                    full_path_for_caddy = f"/{request.user.username}/{alias_input.lstrip('/')}/*"
                    new_route = {
                        "match": [{"path": [full_path_for_caddy]}],
                        "handle": [{
                            "handler": "reverse_proxy",
                            "upstreams": [{"dial": target_url_input}]
                        }]
                    }
                    user_routes.append(new_route) # Añadir a la lista mutable

                    try:
                        user_cfg_obj.save() # Persistir los cambios
                        logger.info(f"Destino externo '{alias_input}' a '{target_url_input}' añadido para '{request.user.username}'.")
                        ok, msg = construir_configuracion_global(iniciado_por=f"Add external target by {request.user.username}")
                        if ok:
                            messages.success(request, f"Destino externo '{alias_input}' configurado y recargado correctamente. {msg}")
                            logger.info(f"Recarga de Caddy exitosa tras añadir destino externo para '{request.user.username}'.")
                        else:
                            messages.error(request, f"Destino externo '{alias_input}' añadido a la base de datos, pero {msg}")
                            logger.warning(f"Fallo en la recarga de Caddy tras añadir destino externo para '{request.user.username}': {msg}")
                    except Exception as e:
                        messages.error(request, f"Error al guardar el destino externo: {e}")
                        logger.exception(f"Error al guardar UserJSON o recargar Caddy para '{request.user.username}' (destinos_externos add).")

        elif action == "delete":
            # Para la acción de eliminar, el alias viene directamente del botón de la tabla
            # en un campo oculto llamado 'alias'.
            if not alias_input: # 'alias_input' es el 'alias' del campo oculto de la tabla
                messages.warning(request, "Debes introducir el alias a eliminar.")
            else:
                route_found_and_removed = False
                # Usamos una lista de copia para iterar y modificamos la original
                for r in list(user_routes):
                    matchers = r.get("match", [])
                    if matchers and matchers[0].get("path"):
                        current_path = matchers[0]["path"][0]
                        expected_prefix_for_alias = f"/{request.user.username}/{alias_input.lstrip('/')}"
                        
                        # Comprobar que es un proxy y que el path coincide con el alias del usuario
                        if current_path.startswith(expected_prefix_for_alias) and current_path.endswith("/*"):
                            handle = r.get("handle", [])
                            if handle and handle[0].get("handler") == "reverse_proxy":
                                user_routes.remove(r) # Eliminar de la lista mutable
                                route_found_and_removed = True
                                break # Salir después de encontrar y eliminar la primera coincidencia
                
                if route_found_and_removed:
                    try:
                        user_cfg_obj.save() # Persistir los cambios
                        logger.info(f"Destino externo '{alias_input}' eliminado para '{request.user.username}'.")
                        ok, msg = construir_configuracion_global(iniciado_por=f"Delete external target by {request.user.username}")
                        if ok:
                            messages.success(request, f"Destino externo '{alias_input}' eliminado y recargado correctamente. {msg}")
                            logger.info(f"Recarga de Caddy exitosa tras eliminar destino externo para '{request.user.username}'.")
                        else:
                            messages.error(request, f"Destino externo '{alias_input}' eliminado de la base de datos, pero {msg}")
                            logger.warning(f"Fallo en la recarga de Caddy tras eliminar destino externo para '{request.user.username}': {msg}")
                    except Exception as e:
                        messages.error(request, f"Error al guardar la eliminación del destino externo: {e}")
                        logger.exception(f"Error al guardar UserJSON o recargar Caddy para '{request.user.username}' (destinos_externos delete).")
                else:
                    messages.warning(request, f"El alias '{alias_input}' no fue encontrado en tus destinos externos o no corresponde a una ruta de proxy de usuario.")
                    logger.info(f"Usuario '{request.user.username}' intentó eliminar alias no existente o no proxy: '{alias_input}'")

        return redirect("destinos_externos") # Redirigir siempre después de un POST para evitar reenvío

    # --- Renderizar la Página ---
    logger.debug(f"Renderizando página de destinos externos para '{request.user.username}' con {len(destinos_para_template)} destinos.")
    return render(request, "destinos_externos.html", { "destinos": destinos_para_template
    })



@login_required # Solo usuarios logueados pueden acceder
def dominios_proxy_view(request):
    """
    Muestra los dominios proxy configurados en Caddy y sus destinos.
    """
    logger.debug(f"Usuario '{request.user.username}' accediendo a la vista de dominios proxy.")

    try:
        # Obtener o crear el objeto UserJSON para el usuario actual.
        user_cfg_obj, created = UserJSON.objects.get_or_create(user=request.user)

        # Si el objeto es nuevo o no tiene datos, inicialízalo con la estructura básica de Caddy.
        if created or not user_cfg_obj.json_data:
            if created:
                logger.info(f"UserJSON creado automáticamente para '{request.user.username}' en dominios_proxy_view.")
            else:
                logger.warning(f"UserJSON de '{request.user.username}' estaba vacío, inicializando en dominios_proxy_view.")

            user_cfg_obj.json_data = {
                "apps": {
                    "http": {
                        "servers": {
                            settings.SERVIDOR_CADDY: {
                                "listen": [f":{settings.CADDY_HTTP_PORT}", f":{settings.CADDY_HTTPS_PORT}"],
                                "routes": []
                            }
                        }
                    }
                }
            }
            user_cfg_obj.save()
            logger.debug(f"Estructura inicial de Caddy guardada para '{request.user.username}'.")

        # Obtener una referencia mutable a las rutas del usuario.
        # Esto asegura que cualquier cambio hecho en 'routes' se refleje en user_cfg_obj.json_data.
        user_routes = user_cfg_obj.json_data \
                        .setdefault("apps", {}) \
                        .setdefault("http", {}) \
                        .setdefault("servers", {}) \
                        .setdefault(settings.SERVIDOR_CADDY, {}) \
                        .setdefault("routes", [])

    except Exception as e:
        messages.error(request, f"Error al cargar la configuración del usuario: {e}")
        logger.exception(f"Error crítico al obtener/inicializar UserJSON para '{request.user.username}' en dominios_proxy_view.")
        
        return redirect("home") # Redirige a home en caso de un error irrecuperable.

    # Lista para almacenar los dominios proxy que se mostrarán en la plantilla.
    proxied_domains_for_template = []

    # Iterar sobre las rutas del usuario para extraer la información de los dominios proxy.
    for route in user_routes:
        hosts = []
        upstreams = []
        is_proxy_route = False

        # Extraer hosts de los matchers.
        for matcher_group in route.get('match', []):
            if 'host' in matcher_group and isinstance(matcher_group['host'], list):
                hosts.extend(matcher_group['host'])

        # Extraer destinos (upstreams) si es una ruta de reverse_proxy.
        for handler_group in route.get('handle', []):
            if handler_group.get('handler') == 'reverse_proxy':
                is_proxy_route = True
                for upstream in handler_group.get('upstreams', []):
                    if 'dial' in upstream:
                        upstreams.append(upstream['dial'])
                break # Solo necesitamos el primer handler de reverse_proxy.

        # Si es una ruta de proxy y tiene hosts y destinos, la añadimos a la lista.
        if is_proxy_route and hosts and upstreams:
            for host in hosts:
                # Opcional: intentar separar host y puerto para visualización si el destino es "host:puerto"
                # Esta lógica ya la teníamos en destinos_externos, la reuso aquí.
                display_destinations = []
                for dest in upstreams:
                    host_part = dest
                    port_part = ""
                    if "://" in dest: # Eliminar esquema para el split de host/port
                        temp_dest = dest.split("://", 1)[1]
                    else:
                        temp_dest = dest

                    if ":" in temp_dest:
                        host_port_split = temp_dest.rsplit(":", 1)
                        if len(host_port_split) == 2 and host_port_split[1].isdigit():
                            host_part, port_part = host_port_split

                    display_destinations.append({
                        "original": dest,
                        "host_display": host_part,
                        "port_display": port_part
                    })

                proxied_domains_for_template.append({
                    'domain': host,
                    'destinations_raw': upstreams, # Para referencia interna si se necesita el formato original
                    'destinations': display_destinations # Para mostrar host/puerto separado
                })

    # --- Manejo de Peticiones POST (Añadir/Eliminar Dominios Proxy) ---
    if request.method == "POST":
        action = request.POST.get("action")
        domain_input = request.POST.get("domain", "").strip() # El dominio que el usuario quiere añadir/eliminar
        target_url_input = request.POST.get("target_url", "").strip() # El destino para el dominio

        logger.info(f"Usuario '{request.user.username}' intentando acción '{action}' en dominios proxy (Dominio: '{domain_input}', Destino: '{target_url_input}').")


        if action == "add":
            if not domain_input or not target_url_input:
                messages.warning(request, "Debes introducir tanto el dominio como la URL de destino.")
            elif not _is_valid_domain(domain_input):
                messages.error(request, f"El dominio '{domain_input}' no es un formato válido.")
            elif not _is_valid_target_url(target_url_input):
                messages.error(request, f"La URL de destino '{target_url_input}' no es un formato válido.")
            else:
                # Comprobar si el dominio ya está siendo proxied por el usuario.
                domain_already_proxied = any(d.get("domain") == domain_input for d in proxied_domains_for_template)

                if domain_already_proxied:
                    messages.info(request, f"El dominio '{domain_input}' ya está siendo proxied. Si quieres cambiar su destino, elimínalo y vuelve a añadirlo.")
                    logger.info(f"Usuario '{request.user.username}' intentó añadir dominio proxy duplicado: '{domain_input}'.")
                else:
                    # Construir la nueva ruta de Caddy para el dominio proxy.
                    new_proxy_route = {
                        "match": [{"host": [domain_input]}],
                        "handle": [{
                            "handler": "reverse_proxy",
                            "upstreams": [{"dial": target_url_input}]
                        }]
                    }
                    user_routes.append(new_proxy_route) # Añadir a la lista mutable.

                    try:
                        user_cfg_obj.save() # Guardar los cambios en la BD.
                        logger.info(f"Dominio proxy '{domain_input}' a '{target_url_input}' añadido para '{request.user.username}'.")
                        
                        # Reconstruir y recargar Caddy.
                        ok, msg = construir_configuracion_global(iniciado_por=f"Add domain proxy by {request.user.username}")
                        if ok:
                            messages.success(request, f"Dominio proxy '{domain_input}' configurado y recargado correctamente. {msg}")
                            logger.info(f"Recarga de Caddy exitosa tras añadir dominio proxy para '{request.user.username}'.")
                        else:
                            messages.error(request, f"Dominio proxy '{domain_input}' añadido a la base de datos, pero {msg}")
                            logger.warning(f"Fallo en la recarga de Caddy tras añadir dominio proxy para '{request.user.username}': {msg}")
                    except Exception as e:
                        messages.error(request, f"Error al guardar el dominio proxy: {e}")
                        logger.exception(f"Error al guardar UserJSON o recargar Caddy para '{request.user.username}' (add domain proxy).")

        elif action == "delete":
            if not domain_input:
                messages.warning(request, "Debes introducir el dominio a eliminar.")
            else:
                route_found_and_removed = False
                # Iterar sobre una copia para poder modificar la lista original.
                for r in list(user_routes):
                    hosts_in_route = []
                    for matcher_group in r.get('match', []):
                        if 'host' in matcher_group and isinstance(matcher_group['host'], list):
                            hosts_in_route.extend(matcher_group['host'])
                    
                    # Verificar si este es el dominio que queremos eliminar Y si es un proxy.
                    if domain_input in hosts_in_route:
                        for handler_group in r.get('handle', []):
                            if handler_group.get('handler') == 'reverse_proxy':
                                user_routes.remove(r) # Eliminar la ruta de la lista.
                                route_found_and_removed = True
                                break # Salir después de encontrar y eliminar.
                    if route_found_and_removed:
                        break # Salir del bucle principal si ya eliminamos.

                if route_found_and_removed:
                    try:
                        user_cfg_obj.save() # Guardar los cambios.
                        logger.info(f"Dominio proxy '{domain_input}' eliminado para '{request.user.username}'.")
                        
                        ok, msg = construir_configuracion_global(iniciado_por=f"Delete domain proxy by {request.user.username}")
                        if ok:
                            messages.success(request, f"Dominio proxy '{domain_input}' eliminado y recargado correctamente. {msg}")
                            logger.info(f"Recarga de Caddy exitosa tras eliminar dominio proxy para '{request.user.username}'.")
                        else:
                            messages.error(request, f"Dominio proxy '{domain_input}' eliminado de la base de datos, pero {msg}")
                            logger.warning(f"Fallo en la recarga de Caddy tras eliminar dominio proxy para '{request.user.username}': {msg}")
                    except Exception as e:
                        messages.error(request, f"Error al guardar la eliminación del dominio proxy: {e}")
                        logger.exception(f"Error al guardar UserJSON o recargar Caddy para '{request.user.username}' (delete domain proxy).")
                else:
                    messages.warning(request, f"El dominio '{domain_input}' no fue encontrado en tus dominios proxy o no corresponde a un proxy gestionado.")
                    logger.info(f"Usuario '{request.user.username}' intentó eliminar dominio proxy no existente: '{domain_input}'.")

        return redirect("dominios_proxy_view") # Redirigir siempre después de un POST.

    # --- Renderizar la Página ---
    context = {
        'dominios': proxied_domains_for_template,
        'domain_proxy_count': len(proxied_domains_for_template),
    }
    logger.debug(f"Renderizando página de dominios proxy para '{request.user.username}' con {context['domain_proxy_count']} dominios.")
    return render(request, 'dominios_proxy.html', context)


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
