""" SISTEMA OPERATIVO """
import datetime
import ipaddress
import os
import json # para poder manejar archivos .json
import requests
import shutil  #  para copiar archivos fácilmente (hacer backup)

""" DJANGO """
from django.shortcuts import render, redirect, get_object_or_404  #  añadimos render para templates 
from django.contrib.auth.models import User # importamos el modelo de usuario que ya trae django
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout # verifica si el username y password son correctos
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.utils.decorators import method_decorator
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt

""" API REST FRAMEWORK """
from rest_framework import status # contiene códigos de estado HTTP estándar
from rest_framework.response import Response # encapsula la respuesta que se enviará al cliente, siguiendo el formato adecuado (JSON).
from rest_framework.decorators import api_view, authentication_classes, permission_classes # convierte la función de vista en una vista basada en función de Django REST Framework
from rest_framework.authentication import TokenAuthentication # esto es para usar la autenticacion por token
from rest_framework.permissions import IsAuthenticated # esto es para darle solo los permisos a los autenticados
from rest_framework.permissions import IsAuthenticatedOrReadOnly # la vista permite escrituras (PUT) a los autenticados, pero permite solo lecturas (GET) a los usuarios no autenticados
from rest_framework.authtoken.models import Token # almacena los tokens de autenticación de los usuarios

""" MANEJO DE LAS VISTAS """
from rest_framework.views import APIView #  clase base para crear vistas de drf
from rest_framework import viewsets # importamos el viewsets para crear modelos CRUD completos muy rápido
from rest_framework.response import Response

""" MODELOS Y SERIALIZERS """

from .models import UserJSON # importamos el modelo para el json de cada usuario
from .serializers import UserRegisterSerializer # importamos el serializador del sistema de registro

""" 🔵🔵🔵 RUTAS NECESARIAS 🔵🔵🔵 """
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Ruta al NUEVO caddy.json GENERADO DINAMICAMENTE
JSON_PATH = os.path.join(BASE_DIR, "deploy", "caddy.json") # Eso construye la ruta relativa correcta al caddy.json aunque estés dentro del contenedor o en local

# Función mejorada para construir el caddy global y recargar Caddy automáticamente
def construir_configuracion_global():
    
    # Primero creamos el json de base
    base = {
        "admin": {"listen": "0.0.0.0:2019"},
        "apps": {
            "http": {
                "servers": {
                    "Cloud_Guardian": {
                        "listen": [":80"],
                        "routes": []
                    }
                }
            }
        }
    }
    
    rutas_globales = base["apps"]["http"]["servers"]["Cloud_Guardian"]["routes"]



    # 1) Sirve /static/* directamente desde el disco
    rutas_globales.append({
        "match": [
            { "path": ["/static/*"] }
        ],
        "handle": [
            {
                "handler": "file_server",
                # pon aquí la ruta absoluta donde está tu carpeta static en el servidor:
                "root": "/home/despliegue-nube/cloudguardian/backend/static"
            }
        ]
    })
    
    # 2) Rutas de usuario... Aqui vamos a recorrer todos los .json de los usuario uniendolos al base para tener un .json con todas las configuraciones
    for ujson in UserJSON.objects.all():
        rutas_globales.extend(ujson.json_data["apps"]["http"]["servers"]["Cloud_Guardian"]["routes"])
    # 3) Catch-all a Django
    rutas_globales.append({
        "handle": [
            {
                "handler": "reverse_proxy",
                "upstreams": [
                    { "dial": "127.0.0.1:8000" }
                ]
            }
        ]
    })


    
    # Ahora guardamos el .json base que hemos creado en caddy.json
    with open(JSON_PATH, "w", encoding = "utf-8") as f:
        json.dump(base, f, indent = 4)

    # Por ultimo recargamos caddy
    try:
        resp = requests.post(
            os.environ.get("CADDY_ADMIN", "http://localhost:2019") + "/load",
            json=base, timeout=2
        )
        if resp.status_code == 200:
            return True, "Configuración global generada correctamente."
        return False, f"Error al recargar Caddy: {resp.status_code} – {resp.text}"
    except requests.exceptions.RequestException as e:
        # Si no podemos conectarnos, lo tratamos como warning en desarrollo
        return True, f"Configuración escrita, pero no se pudo recargar Caddy: {e}"

""" 🔵 VISTAS CLÁSICAS PARA TEMPLATES 🔵 """

""" FUNCIONES DE SUPERUSUARIO: PARA ELIMINAR USUARIOS """
@staff_member_required
def eliminar_usuario(request):
    
    # Obtenemos el usuario a eliminar
    if request.method == "POST":
        username = request.POST.get("username")

        # Comprobamos que usuario existe en la base de datos y lo eliminamos
        try:
            user = User.objects.get(username = username)
            user.delete()  # tambien se elimina su UserJson gracias a on_delete=CASCADE(models.py)

            # Ahora recargamos la configuración global con los cambios(quitando las rutas del usuario eliminado)
            ok, msg = construir_configuracion_global()
            messages.success(request, f"Usuario '{username}' eliminado. {msg}" if ok else f"Usuario eliminado, pero {msg}")
            
        except User.DoesNotExist:
            messages.error(request, f"No existe el usuario '{username}'.")

        return redirect("eliminar_usuario")

    return render(request, "eliminar_usuario.html")

"""  HOME (DASHBOARD)  """
@login_required
def home(request):
    return render(request, "home.html")

# Login y Register no llevan protección
"""  LOGIN  """
def login_view(request):
    
    if request.method == "POST":
        # Primero obtenemos el usuario y contraseña y lo autenticamos
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "").strip()
        
        if not username or not password:
            messages.warning(request, "Debes introducir usuario y contraseña.")
            return redirect("login")
        
        user = authenticate(request, username=username, password=password)
        
        # Luego comprobamos si existe, y si existe entra en su configuracion y ya va a inicio, si no recarga el login
        if user:
            auth_login(request, user)
            messages.success(request, f"Bienvenido {username}!")
            return redirect('home')
        else:
            messages.error(request, "Usuario o contraseña incorrectos.")
            return redirect('login')

    return render(request, "login.html")


"""  REGISTER  """
def register_view(request):
    
    if request.method == "POST":
        # Obtenemos los datos del formulario de registro
        username = request.POST.get("username", "").strip()
        password1 = request.POST.get("password1", "").strip()
        password2 = request.POST.get("password2", "").strip()

        if not username or not password1 or not password2:
            messages.warning(request, "Todos los campos son obligatorios.")
            return redirect("register")
        
        # Comprobamos que las contraseñas son iguales y que no existe un usuario con ese nombre
        if password1 != password2:
            messages.error(request, "Las contraseñas no coinciden.")
            return redirect('register')
        
        if User.objects.filter(username = username).exists():
            messages.error(request, "El nombre de usuario ya existe.")
            return redirect('register')

        # Si todo va bien creamos el usuario nuevo con los datos pasados
        user = User.objects.create_user(username = username, password = password1)

        # Creamos la configuración inicial de usuario por defecto
        default_config = {
            "apps": {
                "http": {
                    "servers": {
                        "Cloud_Guardian": {
                            "listen": [":80"],
                            "routes": []
                        }
                    }
                }
            }
        }
        try:
            UserJSON.objects.create(user=user, json_data=default_config)
            messages.success(request, f"Usuario '{username}' registrado y configuración creada!")
        except Exception as e:
            messages.warning(request, f"Usuario registrado pero error en configuración: {e}")
            
        auth_login(request, user)
        return redirect("home")
    
    return render(request, "register.html")


"""  LOGOUT(cerrar sesión) """
@login_required
def logout_view(request):
    auth_logout(request)
    messages.success(request, "Sesión cerrada correctamente.")
    return redirect('login')


"""  CONFIGURACIÓN GENERAL  """
@login_required
def configuracion(request):
    
    # SUPERUSUARIOS:
    
    # Comprobamos que sea un superusuario
    if request.user.is_superuser:
        
        # SUPERUSUARIO: Muestra y edita el caddy.json global
        try:
            # Abrimos y cargamos el caddy.json global
            with open(JSON_PATH, "r", encoding="utf-8") as f:
                global_config = json.load(f)

            # Si el metodo es POST significa que queremos modificar la configuración
            if request.method == "POST":
                # Guardamos la nueva configuración
                new_config = request.POST.get("config")
                
                try:
                    # Cargamos la nueva configuración
                    data = json.loads(new_config)
                    
                    # Guardamos la nueva configuración sobreescribiendo el caddy.json global si la configuración es válida
                    with open(JSON_PATH, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=4)

                    # Recargamos Caddy
                    response = requests.post(os.environ.get("CADDY_ADMIN", "http://localhost:2019") + "/load", json=data)
                    if response.status_code == 200:
                        messages.success(request, "Configuración global actualizada y recargada correctamente.")
                    else:
                        messages.error(request, "Error al recargar Caddy con la nueva configuración.")
                        
                except json.JSONDecodeError:
                    messages.error(request, "Formato JSON inválido.")
                    
                return redirect("configuracion")

            # Si el metodo usado es GET mostramos el json
            config_json = json.dumps(global_config, indent=4)
            return render(request, "configuracion.html", {
                "config": config_json,
                "es_superuser": True
            })

        # Si hay algún error redirigimos a inicio
        except Exception as e:
            messages.error(request, f"Error al leer el caddy.json global: {e}")
            return redirect("home")
        
    else:
        # USUARIO NORMAL: Muestra y edita su configuración personalizada
    
        try:
            # Obtenemos la configuración del usuario
            user_config = UserJSON.objects.get(user=request.user)
        
        # Si el usuario no tiene configuración redirigimos a home
        except UserJSON.DoesNotExist:
            messages.error(request, "No se encontró configuración para este usuario.")
            return redirect("home")

    # Si el metodo es POST significa que queremos modificar la configuración
    if request.method == "POST":
        # Guardamos la nueva configuración
        new_config = request.POST.get("config")
        
        try:
            # Cargamos los datos de la nueva configuración
            data = json.loads(new_config)
            
            # Los validamos
            user_config.json_data = data
            
            # Los guardamos en la base de datos
            user_config.save()
            
            # Recargamos la configuración global con los cambios del usuario
            ok, msg = construir_configuracion_global()
            messages.success(request, msg) if ok else messages.error(request, msg)

            # Redirigimos a configuración 
            return redirect("configuracion")
        
        except json.JSONDecodeError:
            messages.error(request, "Formato JSON inválido.")

    # Si el método es GET mostramos los datos del json del usuario
    config_json = json.dumps(user_config.json_data, indent=4)
    return render(request, "configuracion.html", {
        "config": config_json,
        "es_superuser": False
    })


"""  IPs BLOQUEADAS  """
@login_required
def ips_bloqueadas(request):
    """
    Vista para gestionar las IPs bloqueadas de cada usuario:
    - Muestra las IPs permitidas y denegadas actuales.
    - Permite agregar o eliminar IPs de bloqueo.
    - Reconstruye la configuración global de Caddy tras cambios.
    """
    allow = []
    deny = []
    
    try:
        # Carga el UserJSON del usuario actual
        user_config = UserJSON.objects.get(user=request.user)
        data = user_config.json_data
        
        # Asegura la estructura apps → http → servers → Cloud_Guardian → routes
        rutas = data.setdefault("apps", {}) \
                    .setdefault("http", {}) \
                    .setdefault("servers", {}) \
                    .setdefault("Cloud_Guardian", {}) \
                    .setdefault("routes", [])

        # Busca, si existe, la ruta de remote_ip específica de este usuario
        ruta_bloqueadas = None
        for r in rutas:
            matcher = r.get("match", [{}])[0]
            if "remote_ip" in matcher and f"/{request.user.username}/" in matcher.get("path", [""])[0]:
                ruta_bloqueadas = r
                break

        # Inicializa allow/deny en la sección de security → remote_ip
        remote = (
            data.setdefault("apps", {})
                .setdefault("http", {})
                .setdefault("security", {})
                .setdefault("remote_ip", {})
        )
        allow = remote.setdefault("allow", [])
        deny = remote.setdefault("deny", [])

        # Si ya existía una ruta personalizada, carga sus rangos actuales
        if ruta_bloqueadas:
            deny[:] = ruta_bloqueadas["match"][0]["remote_ip"].get("ranges", [])

        # Procesa el formulario POST (añadir o eliminar IP)
        if request.method == "POST":
            action = request.POST.get("action")
            ip_add = request.POST.get("ip_add", "").strip()
            ip_del = request.POST.get("ip_delete", "").strip()

            # --- ADD: bloquear una nueva IP ---
            if action == "add":
                # Validación de campo no vacío
                if not ip_add:
                    messages.warning(request, "Debes escribir una IP para bloquear.")
                    return redirect("ips_bloqueadas")
                # Validar formato
                try:
                    ipaddress.ip_network(ip_add)
                except ValueError:
                    messages.error(request, f"La IP «{ip_add}» no es válida.")
                    return redirect("ips_bloqueadas")
                
                if ip_add in deny:
                    messages.info(request, f"La IP {ip_add} ya estaba bloqueada.")
                    return redirect("ips_bloqueadas")

                # Añade al array de deny
                deny.append(ip_add)


                
                # Construye (o actualiza) la ruta de Caddy
                nueva = {
                    "match": [
                        {
                            "path": [f"/{request.user.username}/*"],
                            "remote_ip": {"ranges": deny}
                        }
                    ],
                    "handle": [
                        {
                            "handler": "static_response",
                            "status_code": 403,
                            "body": "IP bloqueada"
                        }
                    ]
                }
                if ruta_bloqueadas:
                    rutas[rutas.index(ruta_bloqueadas)] = nueva
                else:
                    rutas.insert(0, nueva)

                # Guarda cambios en la base de datos
                user_config.json_data = data
                user_config.save()
                
                # Reconstruye y recarga Caddy
                ok, msg = construir_configuracion_global()
                if ok:
                    messages.success(request, f"IP {ip_add} bloqueada correctamente. {msg}")
                else:
                    messages.error(request, f"IP {ip_add} bloqueada pero error recargando Caddy: {msg}")
                return redirect("ips_bloqueadas")

            # --- DELETE: desbloquear una IP existente ---
            if action == "delete":
                # Validación de campo no vacío
                if not ip_del:
                    messages.warning(request, "Debes escribir una IP para desbloquear.")
                    return redirect("ips_bloqueadas")
                # Comprueba que la IP está bloqueada
                if ip_del not in deny:
                    messages.warning(request, f"La IP {ip_del} no está en la lista.")
                    return redirect("ips_bloqueadas")

                # Remueve del array deny
                deny.remove(ip_del)
                
                # Si la ruta existía, actualiza sus rangos o la elimina si quedó vacía
                if ruta_bloqueadas:
                    if deny:
                        # actualiza lista en ruta existente
                        ruta_bloqueadas["match"][0]["remote_ip"]["ranges"] = deny
                    else:
                        # si ya no hay IPs, quita la ruta
                        rutas.remove(ruta_bloqueadas)

                # Guarda cambios
                user_config.json_data = data
                user_config.save()
                
                
                # Reconstruye y recarga Caddy
                ok, msg = construir_configuracion_global()
                if ok:
                    messages.success(request, f"IP {ip_del} desbloqueada correctamente. {msg}")
                else:
                    messages.error(request, f"IP {ip_del} desbloqueada pero error recargando Caddy: {msg}")
                return redirect("ips_bloqueadas")


    except UserJSON.DoesNotExist:
        messages.error(request, "No se encontró configuración para este usuario.")
    except Exception as e:
        messages.error(request, f"Error interno al cargar IPs: {e}")

    # Renderiza la plantilla con las listas actuales
    return render(request, "ips_bloqueadas.html", {
        "allow_ips": allow,
        "deny_ips": deny
    })


"""  RUTAS PROTEGIDAS  """
@login_required
def rutas_protegidas(request):
    """
    Vista que gestiona las rutas protegidas de un usuario:
    - Muestra las rutas actuales
    - Permite añadir una nueva ruta bajo /<username>/
    - Permite eliminar rutas existentes
    - Reconstruye y recarga la configuración global de Caddy
    """
    rutas_mostradas = []
    
        # Obtiene el registro JSON del usuario
    try:
        user_config = UserJSON.objects.get(user=request.user)
        data = user_config.json_data
        
        # Asegura la estructura nested en el JSON y obtiene la lista de rutas
        rutas = (data.setdefault("apps", {})
                    .setdefault("http", {})
                    .setdefault("servers", {})
                    .setdefault("Cloud_Guardian", {})
                    .setdefault("routes", []))

        # Extrae sólo los paths (strings) para renderizar en la plantilla
        
        for r in rutas:
            for m in r.get("match", []):
                rutas_mostradas.extend(m.get("path", []))

        # Si se envía el formulario, procesa ADD o DELETE
        if request.method == "POST":
            action = request.POST.get("action")
            ruta_add = request.POST.get("ruta_add", "").strip()
            ruta_del = request.POST.get("ruta_delete", "").strip()

        # --- ADD ---
        if action == "add":
            # Validaciones básicas
            if not ruta_add:
                messages.warning(request, "Debes escribir una ruta para añadir.")
                return redirect("rutas_protegidas")
            if not ruta_add.startswith(f"/{request.user.username}/"):
                messages.error(request, "Sólo puedes proteger rutas bajo tu usuario.")
                return redirect("rutas_protegidas")
            # Comprueba duplicados
            if any(ruta_add in m.get("path", []) for r in rutas for m in r.get("match", [])):
                messages.info(request, f"La ruta {ruta_add} ya existe.")
                return redirect("rutas_protegidas")

            # Construye la nueva ruta al formato Caddy
            nueva = {
                "match": [{"path": [ruta_add]}],
                "handle": [{"handler": "static_response", "body": f"Acceso permitido a {ruta_add}"}]
            }
                
            # Añade al JSON del usuario y guarda
            rutas.append(nueva)
            user_config.json_data = data
            user_config.save()
                
            # Reconstruye la configuración global y recarga Caddy

            ok, msg = construir_configuracion_global()
            (messages.success if ok else messages.error)(
                request,
                f"Ruta {ruta_add} añadida correctamente. {msg}"
            )
            return redirect("rutas_protegidas")

        # --- DELETE ---
        elif action == "delete":
            if not ruta_del:
                messages.warning(request, "Debes escribir una ruta para eliminar.")
                return redirect("rutas_protegidas")
                
            # Filtra rutas que no coincidan con la ruta a eliminar
            nuevas = [r for r in rutas 
                    if ruta_del not in r.get("match", [{}])[0].get("path", [])]
                
            # Si no cambió el número de rutas, la ruta no existía
            if len(nuevas) == len(rutas):
                messages.warning(request, f"La ruta {ruta_del} no existe.")
                return redirect("rutas_protegidas")

            # Guarda los cambios en el JSON del usuario
            data["apps"]["http"]["servers"]["Cloud_Guardian"]["routes"] = nuevas
            user_config.json_data = data
            user_config.save()
                
            # Reconstruye y recarga Caddy
            ok, msg = construir_configuracion_global()
            (messages.success if ok else messages.error)(
                request,
                f"Ruta {ruta_del} eliminada correctamente. {msg}"
            )
            return redirect("rutas_protegidas")

    except UserJSON.DoesNotExist:
        messages.error(request, "No se encontró configuración para este usuario.")
    except Exception as e:
        messages.error(request, f"Error interno al cargar rutas: {e}")

    # Renderiza la plantilla, pasando únicamente los paths
    return render(request, "rutas_protegidas.html", {
        "rutas": rutas_mostradas
    })




""" 🔴  API ORIGINAL  🔴 """

""" 🟢🟢🟢 REGISTRO DE USUARIOS 🟢🟢🟢"""

@api_view(['POST'])
def register(request):
    
    username = request.data.get("username") # obtenemos el nombre de usuario
    password = request.data.get("password") # obtenemos la contraseña
        
    serializer = UserRegisterSerializer(data = request.data) # creamos una instancia de UserRegisterSerializer y le pasamos los datos que vienen en la petición (request.data)
        
    if serializer.is_valid(): # Verificamos si los datos enviados son válidos, es decir, si cumplen con las reglas del serializador
        usuario = serializer.save() # Llamamos a serializer.save(), que a su vez ejecutará el método create que definimos en el serializador, creando un usuario en la base de datos y le pasamos los datos a la variable user
        Token.objects.create(user = usuario) # creamos un token para el usuario y lo almacena en la tabla Token
            
        user_json_path = os.path.join(BASE_DIR, f"caddy_{usuario.username}.json") # creamos la ruta para el JSON de la base de datos
        
        try:
            # Cargar JSON base
            with open(JSON_PATH, "r", encoding='utf-8') as f:
                data_base = json.load(f) # cargamos los datos del json base en una variable

            # Escribir una copia para el usuario
            with open(user_json_path, "w", encoding="utf-8") as f: # creamos una copia del json base en el json del usuario creado mediante la ruta que creamos antes
                json.dump(data_base, f, indent=4) # dumpeamos los datos del JSON base al JSON del usuario nuevo

                UserJSON.objects.create(user = usuario, json_data = data_base, json_path = user_json_path) # guardamos el nuevo JSON en la base de datos(en la tabla UserJSON que hemos creado)

            construir_configuracion_global()
            
        except Exception as e:
            return Response({"error": f"Error al crear el archivo JSON"}, status = status.HTTP_500_INTERNAL_SERVER_ERROR) # si pasa algo en el proceso mandamos un msg y un codigo de estado

        return Response({"message": "Usuario registrado y JSON generado"}, status = status.HTTP_201_CREATED) # si todo va bien devolvemos esto
        
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

""" 🔴🔴🔴 CLASE Y FUNCION PARA ELIMINAR USUARIOS DE LA BASE DE DATOS 🔴🔴🔴 """

#  Eliminar usuarios
class UserDelete(APIView): # definimos la clase para eliminar usuario
    def post(self, request): # definimos la funcion que recibe la peticion mediante el metodo post
        
        # Elimina un usuario por su nombre de usuario si indican la masterkey necesaria
        username = request.data.get("username") # obtenemos el username de la peticion
        key = request.data.get("masterkey") # obtenemos la masterkey aunque la llamamos key para compararla despues
        masterkey = "delete" # aqui tenemos el valor de la masterkey
        
        if key == masterkey: # si la key es igual a la masterkey dale accesi
            
            try:
                
                user = User.objects.get(username = username) # obtenemos el usuario de la base de datos
                user.delete() # lo borramos de la base de datos(el json se borra automaticamente de la base de datos con el cascade puesto en el modelo)
                
                user_json_path = os.path.join(BASE_DIR, f"caddy_{username}.json") # ruta al fichero del usuario a eliminar
                if os.path.exists(user_json_path):
                    os.remove(user_json_path)
                return Response({"message":f"Usuario: {username} eliminado correctamente"}, status = status.HTTP_202_ACCEPTED) # si todo sale bien
            
            
            except User.DoesNotExist: 
                return Response({"error":f"El usuario: {username} no existe"}, status = status.HTTP_404_NOT_FOUND) # si no existe devolvemos esto
            
        else:
            return Response({"Contraseña maestra incorrecta, no puedes eliminar usuarios"}, status = status.HTTP_203_NON_AUTHORITATIVE_INFORMATION) # si fallas con la masterkey te aparecera esto

""" LISTA DE USUARIOS PARA TESTEAR COSAS """   

#  Listar usuarios
class listarUsers(APIView):
    def get(self, request):
        users = list(User.objects.values())
        jsons = list(UserJSON.objects.values())
        tokens = list(Token.objects.values())
        return Response({"Usuarios": users, "JSONs": jsons, "Tokens": tokens})
    
""" LISTA DE USUARIOS PARA TESTEAR COSAS """   
    

""" 👋👋👋 FUNCIONES PARA INICIO DE SESION Y CIERRE DE SESION 👋👋👋 """
# Login API
@api_view(['POST']) # solo acepta peticiones POST.
def login(request):  #  Define la función login_view 
    
    username = request.data.get("username") # obtenemos el username del cuerpo de la request
    password = request.data.get("password") # obtenemos la password del cuerpo de la request

    user = authenticate(username = username, password = password) # verificamos que las credenciales son correctas

    if user: # si el usuario existe
        token, _ = Token.objects.get_or_create(user = user) # si el usuario no tiene token en la bbdd crea uno para el
        
        try:
            
            user_config = UserJSON.objects.get(user = user) # obtenemos el JSON de la base de datos del user pasado por parametro
            
            construir_configuracion_global()
        except UserJSON.DoesNotExist:
            return Response({"error": f"No existe un JSON para el usuario {user.username}"}, status=404)
        return Response({"token": token.key, "caddy_config": user_config.json_data}, status=200)
    return Response({"error": "Credenciales incorrectas"}, status=401) # si hay algun error devuelve un mensaje y un error 400


# Logout API
@api_view(['POST']) # Solo permite peticiones POST
def logout(request): #  Define la funcion para cerrar sesion de usuario eliminando el token 
    token_header = request.headers.get('Authorization')
    
    if not token_header:
        return Response({'error': 'No se proporcionó token en la solicitud'}, status = status.HTTP_400_BAD_REQUEST) # si no existe e token lo decimos y mandamos un error 400
    token = token_header.replace("Token ", "").strip()
    try:
        Token.objects.get(key=token).delete()  # borrar el token del usuario
        return Response({'message': 'Logout exitoso, token eliminado.'}, status=status.HTTP_200_OK) # si se ha eliminado mandamos un msg y un estado 200
    except Token.DoesNotExist:
        return Response({'error': 'Token inválido o ya expirado.'}, status=status.HTTP_400_BAD_REQUEST) # si se ha pasado un token pero no es valido o ya a expirado


""" 🖥️🖥️🖥️ FUNCION PARA LEER O MODIFICAR EL JSON PARA VER O MODIFICAR SU CONFIGURACION 🖥️🖥️🖥️ """

# Leer o modificar configuración caddy.json
@api_view(['GET', 'PUT']) # configuramos la vista para manejar los métodos HTTP GET y PUT
@authentication_classes([TokenAuthentication]) # es para autenticar el token automaticamente
@permission_classes([IsAuthenticated]) # solo los autenticados pueden modificar, los demas solo lectura
def caddy_config_view(request): # definimos la funcion que va a leer o modificar el .json
    
    # JSON_PATH = '/etc/caddy/caddy.json'  # Ruta dentro del contenedor
    
    user = request.user  # el usuario es automáticamente autenticado por DRF
        
    try:
        user_config = UserJSON.objects.get(user = user) # obtenemos los datos del JSON del user autenticado de la base de datos y los metemos en el objeto user_config
            
    except UserJSON.DoesNotExist:
        return Response({"error": "No se encontró configuración para este usuario."}, status=status.HTTP_404_NOT_FOUND) # si no existe devuelve esto

    # Esta es la funcion para el GET 
    if request.method == 'GET':
        return Response(user_config.json_data) # devuelve simplemente los datos de dentro del user_config

    #  Esta es la funcion para el PUT 
    elif request.method == 'PUT':
        new_config = request.data # metemos la nueva configuracion en una variable, esta nueva configuracion la hemos obtenido de la peticion

        if not isinstance(new_config, dict): # comprobamos que los datos que nos han mandado son en formato diccionario
            return Response({'error': 'El JSON enviado no es válido.'}, status = status.HTTP_400_BAD_REQUEST) # en caso de que no sea en formato diccionario devolvemos un error 400

        user_config.json_data = new_config # le pasamos la nueva configuracion a nuestra configuracion
        user_config.save() # lo guardamos en la base de datos
        construir_configuracion_global()

        return Response({"message": "Configuración actualizada correctamente."}, status=status.HTTP_200_OK) # si todo va bien devolvemos esto
        
""" CLASES PARA AÑADIR Y ELIMINAR IPS PERMITIDAS Y BLOQUEADAS """
# Añadir IPs
class AddIPs(APIView): #  Esta es la clase para añadir ips al json 
    
    def post(self, request): # funcion que recibe una peticion mediante el metodo post
        
        new_ips_allow = request.data.get("allow-ips") # obtenemos las ips a permitir de la peticion
        new_ips_deny = request.data.get("deny-ips") # obtenemos las ips a bloquear de la peticion
        
        try: 
            
            with open(JSON_PATH, 'r+', encoding="utf-8") as f: # abrimos nuestro caddy.json
                data = json.load(f) # cargamos todos los datos en una variable data
                
                ips_allow = data["apps"]["http"]["security"]["remote_ip"]["allow"] # lista de ips permitidas
                ips_deny = data["apps"]["http"]["security"]["remote_ip"]["deny"] # lista de ips denegadas
                
                
                if new_ips_allow:
                    ips_allow.append(new_ips_allow)
                    
                if new_ips_deny:
                    ips_deny.append(new_ips_deny)
                    
                    # Sobreescribir el archivo JSON con los nuevos datos
                    f.seek(0)  # Ir al inicio del archivo
                    json.dump(data, f, indent=4) # dumpeamos los datos
                    f.truncate()  # Ajustar el tamaño del archivo
                    
                    return Response({"message": "IPs añadidas correctamente"}, status=status.HTTP_201_CREATED) # si todo sale bien devolvemos esto
        except:
            
            return Response({"error": "Error al añadir IPs"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR) # si hay algun error en el proceso devolvemos esto

#  Eliminar IPs
class DeleteIPs(APIView): #  clase para eliminar ips 
    
    def post(self, request): # funcion que decibe la peticion del cliente mediante el metodo post
        
        delete_ips_allow = request.data.get("allow-ips") # obtenemos las ips permitidas a eliminar 
        delete_ips_deny = request.data.get("deny-ips") # obtenemos las ips bloqueadas a eliminar
        
        try: 
            
            with open(JSON_PATH, 'r+', encoding="utf-8") as f: # abrimos nuestro json
                data = json.load(f) # cargamos los datos
                
                ips_allow = data["apps"]["http"]["security"]["remote_ip"].setdefault("allow", []) # lista de ips permitidas
                ips_deny = data["apps"]["http"]["security"]["remote_ip"].setdefault("deny", []) # lista de ips denegadas
                
                if delete_ips_allow:
                    if delete_ips_allow in ips_allow:
                        ips_allow.remove(delete_ips_allow)
                if delete_ips_deny:
                    if delete_ips_deny in ips_deny:
                        ips_deny.remove(delete_ips_deny)
                    
                    # Sobreescribir el archivo JSON con los nuevos datos
                    f.seek(0)  # Ir al inicio del archivo
                    json.dump(data, f, indent=4) # dumpeamos los datos
                    f.truncate()  # Ajustar el tamaño del archivo
                    
                    return Response({"message": f"IPs permitidas: '{delete_ips_allow}' y IPs denegadas '{delete_ips_deny}' eliminadas correctamente"}, status=status.HTTP_201_CREATED) # si todo a ido bien devolvemos esto
                
                else: # si alguna de las ips que se pasan no existen en el caddy.json devolvemos este msg y status
                    return Response({"message":"Alguna de las ips añadidas no existe, porfavor vuelve a revisarlo y añade ips que esten añadidas"}, status = status.HTTP_400_BAD_REQUEST)
                
        except:
            
            Response({"message":"Ha ocurrido un error al intentar añadir las ips"}, status = status.HTTP_500_INTERNAL_SERVER_ERROR) # si ocurre otro error en el proceso devolvemos esto
            
""" 🛤️🛤️🛤️ CREAMOS CLASE Y FUNCIONES PARA AÑADIR Y ELIMINAR RUTAS PROTEGIDAS 🛤️🛤️🛤️ """
#  Añadir rutas protegidas
class AddRoutes(APIView): #  clase para añadir rutas protegidas 
    
    def post(self, request):
        
        new_path = request.data.get("path")  # ruta que queremos agregar
        users = {user.username: user.password for user in User.objects.all()} # usuarios de la base de datos

        if not new_path:
            return Response({"error": "Añade alguna ruta"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            
            with open(JSON_PATH, "r+", encoding = "utf-8") as f:
                data = json.load(f)

                # Acceder a la lista de rutas en Caddy
                routes = data["apps"]["http"]["servers"]["Cloud_Guardian"].setdefault("routes", [])

                # Comprobar si la ruta ya existe
                for route in routes:
                    for match in route.get("match", []):
                        if "path" in match and new_path in match["path"]:
                            return Response({"error": f"La ruta '{new_path}' ya existe"}, status=status.HTTP_400_BAD_REQUEST)

                # Crear la nueva ruta protegida
                new_route = {
                    "match": [{"path": [new_path]}],
                    "handle": [
                        {
                            "handler": "rate_limit",
                            "rate_limit": {
                                "requests": 5,  # Máximo de 5 requests por minuto
                                "window": "1m"
                            }
                        },
                        {
                            "handler": "authenticate",
                            "basic": {
                                "users": users
                            }
                        },
                        {
                            "handler": "static_response",
                            "body": f"Acceso permitido a {new_path}"
                        }
                    ]
                }

                # Agregar la nueva ruta al JSON
                routes.append(new_route)

                # Guardar cambios en el archivo JSON
                f.seek(0)
                json.dump(data, f, indent = 4)
                f.truncate()

            return Response({"message": f"Ruta segura '{new_path}' añadida correctamente"}, status=status.HTTP_201_CREATED)
        
        except:
            return Response({"error":"Ha ocurrido algún error en el proceso."}, status = status.HTTP_500_INTERNAL_SERVER_ERROR)
        
#  Eliminar rutas protegidas
class DeleteRoutes(APIView): #  clase para eliminar rutas protegidas 

    def post(self, request): # definimos la funcion que recibe la peticion mediante el metodo post
        
        delete_path = request.data.get("path") # recibe el path de la peticion
        
        if not delete_path: # si se ha puesto ningun path se devuleve un msg y status
            return Response({"error":"No has añadido ninguna ruta, porfavor añade una ruta."}, status = status.HTTP_400_BAD_REQUEST)
        
        try:
            
            with open(JSON_PATH, "r+", encoding = "utf-8") as f:
                data = json.load(f)

                routes = data["apps"]["http"]["servers"]["Cloud_Guardian"].get("routes", []) # Acceder a la lista de rutas en Caddy

                # Ahora vamos a generar una lista de rutas en la cual no vamos a incluis la ruta que hemos pasado en la peticion, es decir que vamos a recorrer todas nuestras rutas y las vamos a ir metiendo en esta lista, en el momento que alguna ruta coincida con la ruta obtenida en la peticion esta no la va a incluir, de modo que estamos creando una lista de rutas con las mismas rutas que tenemos en nuestro caddy.json salvo la ruta que hemos obtenido en la peticion, es decir la ruta que contiene nuestra variable delete_path, una vez hecho esto para comprobar que se ha eliminado comparamos la lista que acabamos de generar con la lista de nuestro caddy.json, si el número de rutas es el mismo quiere decir que no se habrá eliminado ninguna ruta con lo cual la ruta que recibimos de la petición no existe en nuestro caddy.json y por lo tanto devolveremos un error
                new_routes = [route for route in routes if all(delete_path not in match.get("path", []) for match in route.get("match", []))] 

                if len(new_routes) == len(routes):
                    return Response({"error": f"La ruta '{delete_path}' no existe"}, status=status.HTTP_404_NOT_FOUND) # si tenemos las mismas rutas en el las nuevas(con la ruta ya eliminada, que en el otro es porque no existe la ruta)

                data["apps"]["http"]["servers"]["Cloud_Guardian"]["routes"] = new_routes # actualizamos la lista de rutas en el JSON

                # Guardar cambios en el archivo JSON
                f.seek(0)
                json.dump(data, f, indent=4)
                f.truncate()

                return Response({"message": f"Ruta '{delete_path}' eliminada correctamente"}, status = status.HTTP_200_OK) # si todo está correcto devolvemos un msg y un status
                        
        except:
            
            return Response({"message": "Ha habido un error en el proceso."}, status = status.HTTP_500_INTERNAL_SERVER_ERROR) # por si ha habido algún error inesperado