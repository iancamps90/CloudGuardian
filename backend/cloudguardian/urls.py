from django.urls import path
from .views import (
    home_view, login_view, register_view, logout_view, configuracion, ips_bloqueadas, rutas_protegidas,
    eliminar_usuario, subdominios_view #, dominios_proxy_view
)
# importamos las funciones y clases creadas en views

from rest_framework.authtoken.views import obtain_auth_token  # importamos la vista que Django proporciona para obtener tokens

urlpatterns = [
    # Vistas normales (Templates)
    path('', home_view, name='home'),
    
    path('login/', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('logout/', logout_view, name='logout'),
    
    path('configuracion/', configuracion, name='configuracion'),
    path('ips-bloqueadas/', ips_bloqueadas, name='ips_bloqueadas'),
    path('rutas-protegidas/', rutas_protegidas, name='rutas_protegidas'),
    
    # path('dominios_proxy/', dominios_proxy_view, name='dominios_proxy_view'),
    path("subdominios/", subdominios_view, name="subdominios_view"),

    
    # URL para eliminar usuario (superuser, template)
    path('eliminar-usuario/', eliminar_usuario, name='eliminar_usuario'),

    # API Endpoints
    #path('api/register/', register, name='api-register'),
    #path('api/login/', login, name='api-login'),
    #path('api/logout/', logout, name='api-logout'),
    #path('api/user-delete/', UserDelete.as_view(), name='user-delete'),
    #path('api/lista/', listarUsers.as_view(), name='lista'),
    #path('api/config/', caddy_config_view, name='configuration'),
    #path('api/ips-bloqueadas/add/', AddIPs.as_view(), name='ips-added'),
    #path('api/ips-bloqueadas/delete/', DeleteIPs.as_view(), name='ips-deleted'),
    #path('api/rutas-protegidas/add/', AddRoutes.as_view(), name='routes-added'),
    #path('api/rutas-protegidas/delete/', DeleteRoutes.as_view(), name='routes-deleted'),
    #path("usuarios/eliminar/", eliminar_usuario, name="eliminar_usuario"),
]