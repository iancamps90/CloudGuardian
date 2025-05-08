""" SISTEMA OPERATIVO """
import datetime
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

    for ujson in UserJSON.objects.all():
        rutas = ujson.json_data["apps"]["http"]["servers"]["Cloud_Guardian"]["routes"]
        base["apps"]["http"]["servers"]["Cloud_Guardian"]["routes"].extend(rutas)

    # Sobrescribe el caddy.json global
    with open(JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(base, f, indent=4)

    # Recarga en Caddy
    try:
        response = requests.post(os.environ.get("CADDY_ADMIN", "http://localhost:2019") + "/load", json=base)
        if response.status_code != 200:
            return False, "Configuración fusionada, pero error al recargar Caddy."
        return True, "Configuración global generada correctamente."
    except Exception as e:
        return False, f"Error recargando Caddy: {e}"


""" 🔵 VISTAS CLÁSICAS PARA TEMPLATES 🔵 """

""" FUNCIONES DE SUPERUSUARIO: PARA VER EL caddy.json GLOBAL Y PARA ELIMINAR USUARIOS """

@staff_member_required
def ver_caddy_json_global(request):
    with open(JSON_PATH, "r", encoding="utf-8") as f:
        config = json.load(f)
    return render(request, "config_global.html", {"config": json.dumps(config, indent=4)})

@staff_member_required
def eliminar_usuario(request):
    if request.method == "POST":
        username = request.POST.get("username")

        try:
            user = User.objects.get(username=username)
            user.delete()  # Esto elimina también el UserJSON si tiene on_delete=CASCADE

            ok, msg = construir_configuracion_global()

            messages.success(request, f"Usuario '{username}' eliminado. {msg}" if ok else f"Usuario eliminado, pero {msg}")
        except User.DoesNotExist:
            messages.error(request, f"No existe el usuario '{username}'.")

        return redirect("eliminar_usuario")

    return render(request, "eliminar_usuario.html")


"""  HOME (DASHBOARD)  """
@login_required  # vista a proteger
def home(request):
    return render(request, "home.html")

"""  LOGIN  """
def login_view(request): # Login y Register no llevan protección 
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
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
        username = request.POST.get('username')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if password1 != password2:
            messages.error(request, "Las contraseñas no coinciden.")
            return redirect('register')
        if User.objects.filter(username=username).exists():
            messages.error(request, "El nombre de usuario ya existe.")
            return redirect('register')

        user = User.objects.create_user(username=username, password=password1)

        # Crear configuración inicial de usuario
        try:
            # Crear configuración inicial por defecto
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
            UserJSON.objects.create(user=user, json_data=default_config)

            messages.success(request, f"Usuario '{username}' registrado exitosamente y configuración creada!")
        except Exception as e:
            messages.warning(request, f"Usuario registrado pero error creando su configuración: {e}")

        auth_login(request, user)
        return redirect("home")

    return render(request, "register.html")

"""  LOGOUT  """
@login_required
def logout_view(request):
    auth_logout(request)
    messages.success(request, "Sesión cerrada correctamente.")
    return redirect('login')


"""  CONFIGURACIÓN GENERAL  """
@login_required
def configuracion(request):
    
    # SUPERUSUARIOS:
    
    if request.user.is_superuser:
        try:
            with open(JSON_PATH, "r", encoding="utf-8") as f:
                global_config = json.load(f)

            if request.method == "POST":
                new_config = request.POST.get("config")
                try:
                    data = json.loads(new_config)
                    with open(JSON_PATH, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=4)

                    # Recargar Caddy
                    response = requests.post(os.environ.get("CADDY_ADMIN", "http://localhost:2019") + "/load", json=data)
                    if response.status_code == 200:
                        messages.success(request, "Configuración global actualizada y recargada correctamente.")
                    else:
                        messages.error(request, "Error al recargar Caddy con la nueva configuración.")
                except json.JSONDecodeError:
                    messages.error(request, "Formato JSON inválido.")
                return redirect("configuracion")

            config_json = json.dumps(global_config, indent=4)
            return render(request, "configuracion.html", {
                "config": config_json,
                "es_superuser": True
            })

        except Exception as e:
            messages.error(request, f"Error al leer el caddy.json global: {e}")
            return redirect("home")
        
    # USUARIOS NORMALES:
    
    try:
        user_config = UserJSON.objects.get(user=request.user)
    except UserJSON.DoesNotExist:
        messages.error(request, "No se encontró configuración para este usuario.")
        return redirect("home")

    if request.method == "POST":
        new_config = request.POST.get("config")
        try:
            data = json.loads(new_config)
            user_config.json_data = data
            user_config.save()
            ok, msg = construir_configuracion_global()
            messages.success(request, msg) if ok else messages.error(request, msg)

            return redirect("configuracion")
        except json.JSONDecodeError:
            messages.error(request, "Formato JSON inválido.")

    config_json = json.dumps(user_config.json_data, indent=4)
    return render(request, "configuracion.html", {"config": config_json})

"""  IPs BLOQUEADAS  """
@login_required
def ips_bloqueadas(request):
    deny = []
    try:
        user_config = UserJSON.objects.get(user = request.user)
        data = user_config.json_data

        rutas = data["apps"]["http"]["servers"]["Cloud_Guardian"]["routes"]

        # Vamos a buscar la ruta para IPs bloqueadas del usuario actual
        ruta_bloqueadas = None  # Valor por defecto si no se encuentra ninguna

        for ruta in rutas:
            match = ruta.get('match', [{}])
            if match and 'remote_ip' in match[0]:
                path = match[0].get('path', [""])
            if path and f"/{request.user.username}/" in path[0]:
                ruta_bloqueadas = ruta
                break  # Salimos porque ya encontramos la primera coincidencia


        if ruta_bloqueadas:
            deny = ruta_bloqueadas['match'][0]['remote_ip']['ranges']
        else:
            deny = []

        if request.method == "POST":
            action = request.POST.get("action")

            if action == "add":
                ip_add = request.POST.get("ip_add")
                if ip_add and ip_add not in deny:
                    deny.append(ip_add)
                    messages.success(request, f"IP {ip_add} bloqueada correctamente.")

            elif action == "delete":
                ip_delete = request.POST.get("ip_delete")
                if ip_delete and ip_delete in deny:
                    deny.remove(ip_delete)
                    messages.success(request, f"IP {ip_delete} eliminada correctamente.")

            # Actualizar o eliminar ruta según si hay IPs bloqueadas
            if deny:
                nueva_ruta_bloqueadas = {
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
                    rutas[rutas.index(ruta_bloqueadas)] = nueva_ruta_bloqueadas
                else:
                    rutas.insert(0, nueva_ruta_bloqueadas)

            else:
                if ruta_bloqueadas:
                    rutas.remove(ruta_bloqueadas)

            # Guardar JSON y recargar config Caddy
            user_config.json_data = data
            user_config.save()

            ok, msg = construir_configuracion_global()
            messages.success(request, msg) if ok else messages.error(request, msg)

    except Exception as e:
        messages.error(request, f"Error cargando configuración de IPs: {e}")

    return render(request, "ips_bloqueadas.html", {"deny_ips": deny})


"""  RUTAS PROTEGIDAS  """
@login_required
def rutas_protegidas(request):
    rutas = []
    try:
        user_config = UserJSON.objects.get(user=request.user)
        data = user_config.json_data

        routes = data.get("apps", {}).get("http", {}).get("servers", {}).get("Cloud_Guardian", {}).get("routes", [])

        for route in routes:
            for match in route.get("match", []):
                rutas.extend(match.get("path", []))

        if request.method == "POST":
            action = request.POST.get("action")
            if action == "add":
                ruta_add = request.POST.get("ruta_add")
                if ruta_add and ruta_add not in rutas:
                    new_route = {
                        "match": [{"path": [ruta_add]}],
                        "handle": [{"handler": "static_response", "body": f"Acceso permitido a {ruta_add}"}]
                    }
                    routes.append(new_route)
                    
                    if not ruta_add.startswith(f"/{request.user.username}/"):
                        messages.error(request, "Solo puedes crear rutas bajo tu nombre de usuario.")
                        return redirect("rutas_protegidas")

                    user_config.json_data = data
                    ok, msg = construir_configuracion_global()
                    messages.success(request, msg) if ok else messages.error(request, msg)
                    user_config.save()
                    return redirect("rutas_protegidas")
            elif action == "delete":
                ruta_delete = request.POST.get("ruta_delete")
                new_routes = [r for r in routes if ruta_delete not in r.get("match", [{}])[0].get("path", [])]
                if len(new_routes) != len(routes):
                    data["apps"]["http"]["servers"]["Cloud_Guardian"]["routes"] = new_routes
                    user_config.json_data = data
                    ok, msg = construir_configuracion_global()
                    messages.success(request, msg) if ok else messages.error(request, msg)
                    user_config.save()
                    return redirect("rutas_protegidas")

    except Exception as e:
        messages.error(request, f"Error cargando configuración de rutas: {e}")

    return render(request, "rutas_protegidas.html", {"rutas": rutas})






""" 🔴  API ORIGINAL  🔴 """

""" 🟢🟢🟢 REGISTRO DE USUARIOS 🟢🟢🟢"""

@api_view(['POST'])
def register(request):
    
    username = request.data.get("username") # obtenemos el nombre de usuario
    password = request.data.get("password") # obtenemos la contraseña
        
    serializer = UserRegisterSerializer(data = request.data) # creamos una instancia de UserRegisterSerializer y le pasamos los datos que vienen en la petición (request.data)
        
    if serializer.is_valid(): # Verificamos si los datos enviados son válidos, es decir, si cumplen con las reglas del serializador
        usuario = serializer.save() # Llamamos a serializer.save(), que a su vez ejecutará el método create que definimos en el serializador, creando un usuario en la base de datos y le pasamos los datos a la variable user
        token = Token.objects.create(user = usuario) # creamos un token para el usuario y lo almacena en la tabla Token
            
        user_json_path = os.path.join(BASE_DIR, f"caddy_{usuario.username}.json") # creamos la ruta para el JSON de la base de datos
        
        try:
            # Cargar JSON base
            with open(JSON_PATH, "r", encoding='utf-8') as f:
                data_base = json.load(f) # cargamos los datos del json base en una variable

            # Escribir una copia para el usuario
            with open(user_json_path, "w", encoding="utf-8") as f: # creamos una copia del json base en el json del usuario creado mediante la ruta que creamos antes
                json.dump(data_base, f, indent=4) # dumpeamos los datos del JSON base al JSON del usuario nuevo

                UserJSON.objects.create(user = usuario, json_data = data_base, json_path = user_json_path) # guardamos el nuevo JSON en la base de datos(en la tabla UserJSON que hemos creado)

            reload_caddy(request, data_base) # recargamos caddy
            
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
                os.remove(user_json_path) # eliminamos su fichero
                    
                return Response({"message":f"Usuario: {username} eliminado correctamente"}, status = status.HTTP_202_ACCEPTED) # si todo sale bien
            
            
            except User.DoesNotExist: 
                return Response({"error":f"El usuario: {username} no existe"}, status = status.HTTP_404_NOT_FOUND) # si no existe devolvemos esto
            
        else:
            return Response({"Contraseña maestra incorrecta, no puedes eliminar usuarios"}, status = status.HTTP_203_NON_AUTHORITATIVE_INFORMATION) # si fallas con la masterkey te aparecera esto

""" LISTA DE USUARIOS PARA TESTEAR COSAS """   

#  Listar usuarios
class listarUsers(APIView):
    def get(self, request):
        usersList = User.objects.values()
        jsonList = UserJSON.objects.values()
        userToken = Token.objects.values()
        return Response({
            "Usuarios": list(usersList),
            "JSONs": list(jsonList),
            "Tokens": list(userToken)
        })
    
""" LISTA DE USUARIOS PARA TESTEAR COSAS """   
    

""" 👋👋👋 FUNCIONES PARA INICIO DE SESION Y CIERRE DE SESION 👋👋👋 """
# Login API
@api_view(['POST']) # solo acepta peticiones POST.
def login(request):  # ✅✅✅ Define la función login_view ✅✅✅
    
    username = request.data.get("username") # obtenemos el username del cuerpo de la request
    password = request.data.get("password") # obtenemos la password del cuerpo de la request

    user = authenticate(username = username, password = password) # verificamos que las credenciales son correctas

    if user: # si el usuario existe
        token, created = Token.objects.get_or_create(user = user) # si el usuario no tiene token en la bbdd crea uno para el
        
        try:
            
            user_config = UserJSON.objects.get(user = user) # obtenemos el JSON de la base de datos del user pasado por parametro
            json_data = user_config.json_data  # extraemos los datos JSON guardados
            
            reload_caddy(request, json_data) # recargamos caddy
            
        except UserJSON.DoesNotExist:
            return Response({f"No existe un JSON para el usuario: {user}"}, status = status.HTTP_404_NOT_FOUND) # si no existe
            
        return Response({
            "token": token.key,
            "caddy_config": json_data
        }, status=status.HTTP_200_OK) # devuelve el token, el contenido del json y el codigo de estado 200
    
    return Response({"error": "Credenciales incorrectas"}, status = status.HTTP_401_UNAUTHORIZED) # si hay algun error devuelve un mensaje y un error 400


# Logout API
@api_view(['POST']) # Solo permite peticiones POST
def logout(request): # ❌❌❌ Define la funcion para cerrar sesion de usuario eliminando el token ❌❌❌
    
    try:
        
        token = request.headers.get('Authorization') # obtener el token desde los headers de autorización.

        if not token:
            return Response({'error': 'No se proporcionó token en la solicitud'}, status = status.HTTP_400_BAD_REQUEST) # si no existe e token lo decimos y mandamos un error 400

        # CORRECTO: quitar "Token " del principio
        token = token.replace("Token ", "").replace('"', '').strip()

        user_token = Token.objects.get(key=token) # buscar el token en la base de datos.

        user_token.delete()  # borrar el token del usuario

        return Response({'message': 'Logout exitoso, token eliminado.'}, status=status.HTTP_200_OK) # si se ha eliminado mandamos un msg y un estado 200

    except Token.DoesNotExist:
        return Response({'error': 'Token no válido o ya expirado.'}, status=status.HTTP_400_BAD_REQUEST) # si se ha pasado un token pero no es valido o ya a expirado

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
                
                ips_allow = data["apps"]["http"]["security"]["remote_ip"]["allow"] # lista de ips permitidas
                ips_deny = data["apps"]["http"]["security"]["remote_ip"]["deny"] # lista de ips denegadas
                
                if not delete_ips_allow and not delete_ips_deny: # comprobamos que se haya añadido alguna ip sino devolvemos msg y status
                    return Response({"message":"No se ha añadido ninguna IP, vuelva a intentarlo."}, status = status.HTTP_400_BAD_REQUEST)
                
                if delete_ips_allow in ips_allow or delete_ips_deny in ips_deny: # comprobamos que las ips recibidas en la peticion esten en el caddy.json
                    if delete_ips_allow:
                        ips_allow.remove(delete_ips_allow) # borramos las permitidas si nos las han pasado
                    if delete_ips_deny:
                        ips_deny.remove(delete_ips_deny) # borramos las denegadas si nos las han pasado
                    
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
                routes = data["apps"]["http"]["servers"]["Cloud_Guardian"]["routes"]

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

                routes = data["apps"]["http"]["servers"]["Cloud_Guardian"]["routes"] # Acceder a la lista de rutas en Caddy

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