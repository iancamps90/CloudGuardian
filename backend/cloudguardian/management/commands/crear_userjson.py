from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from cloudguardian.models import UserJSON
import json
import os

class Command(BaseCommand):
    help = "Crear UserJSON para un usuario específico"

    def add_arguments(self, parser):
        parser.add_argument('--user', type=str, help='Username del usuario')

    def handle(self, *args, **options):
        username = options['user']

        if not username:
            self.stdout.write(self.style.ERROR('Debes indicar el username con --user'))
            return

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            self.stdout.write(self.style.ERROR(f"Usuario '{username}' no encontrado"))
            return

        # Ruta absoluta (ajústala si cambia)
        caddy_path = r"C:\Users\USUARIO\Desktop\fct\FIREWALL\cloudguardian-deploy\deploy\caddy.json"

        if not os.path.exists(caddy_path):
            self.stdout.write(self.style.ERROR("No se encontró el archivo caddy.json"))
            return

        with open(caddy_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Crear el UserJSON
        user_json, created = UserJSON.objects.get_or_create(
            user=user,
            defaults={'json_data': data}
        )

        if created:
            self.stdout.write(self.style.SUCCESS(f"UserJSON creado correctamente para '{username}'"))
        else:
            self.stdout.write(self.style.WARNING(f"Ya existía un UserJSON para '{username}'"))
