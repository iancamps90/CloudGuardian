
from django.contrib.auth.models import User
from django.db import models
from django.db.models import JSONField


# Vamos a crear un modelo para guardar los JSON
class UserJSON(models.Model):
    # le decimos que cada usuario solo podra tener 1 caddy.json y que cuando se elimine el usuario tambien se elimine el json
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="caddy_config") 
    json_data = JSONField(default=dict)  # guarda el contenido del JSON en la base de datos
    
    
    def __str__(self):
        return f"JSON for {self.user.username}"

