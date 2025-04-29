# Los serializadores conviertes de datos de python en JSON y viceversa

from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.authtoken.models import Token


class UserRegisterSerializer(serializers.ModelSerializer): # Creamos una clase UserRegisterSerializer que hereda de serializers.ModelSerializer. Este tipo de serializador nos permite convertir modelos de Django en JSON y viceversa de manera sencilla
    password = serializers.CharField(write_only=True) # para que no se muestre en las respuestas JSON por seguridad

    class Meta:
        model = User # modelo a usar
        fields = ['username', 'password'] # campos del modelo a usar

    def create(self, validated_data): # metodo que se ejecuta cuando el serializador crea un usuario
        usuario = User.objects.create_user(**validated_data) # Llamamos al método create_user del modelo User, que automáticamente cifra la contraseña antes de guardarla
        usuario.set_password(validated_data['password'])  # cifra la contraseña
        usuario.save()
        return usuario
        
