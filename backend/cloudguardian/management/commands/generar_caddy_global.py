import os
import json

from django.core.management.base import BaseCommand
from cloudguardian.models import UserJSON

class Command(BaseCommand):
    help = 'Genera un caddy.json global combinando todos los UserJSON de usuarios, con IPs bloqueadas individualmente'

    def handle(self, *args, **kwargs):
        # Definir la base y el path de deploy
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        deploy_dir = os.path.join(BASE_DIR, "deploy")
        output_caddy_path = os.path.join(deploy_dir, "caddy.json")

        print(f"🔍 Buscando UserJSON en base de datos...")

        users_json = UserJSON.objects.all()

        # Estructura base del nuevo caddy.json
        caddy_config = {
            "admin": {
                "listen": "0.0.0.0:2019"
            },
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

        for user_json in users_json:
            username = user_json.user.username
            print(f"🛠️ Generando ruta para usuario: {username}")

            user_data = user_json.json_data

            # Extraer IPs bloqueadas/permitidas si existen
            security = user_data.get("apps", {}).get("http", {}).get("security", {}).get("remote_ip", {})

            allow = security.get("allow", [])
            deny = security.get("deny", [])

            # Crear handlers
            handlers = []

            if allow or deny:
                handlers.append({
                    "handler": "remote_ip",
                    "allow": allow,
                    "deny": deny
                })

            handlers.append({
                "handler": "static_response",
                "body": f"Acceso permitido a {username}"
            })

            # Crear ruta para el usuario
            route = {
                "match": [
                    {
                        "path": [f"/{username}/*"]
                    }
                ],
                "handle": handlers
            }

            caddy_config["apps"]["http"]["servers"]["Cloud_Guardian"]["routes"].append(route)

        # Guardar el nuevo caddy.json
        os.makedirs(deploy_dir, exist_ok=True)
        with open(output_caddy_path, "w", encoding="utf-8") as f:
            json.dump(caddy_config, f, indent=4)

        self.stdout.write(self.style.SUCCESS(f'✅ Caddy global generado correctamente en {output_caddy_path}'))
