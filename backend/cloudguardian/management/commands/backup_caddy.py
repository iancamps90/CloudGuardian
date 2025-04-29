from django.core.management.base import BaseCommand
import shutil
import os
import datetime

class Command(BaseCommand):
    help = "Crear un backup del archivo caddy.json"

    def handle(self, *args, **options):
        try:
            # Ruta original del caddy.json
            caddy_path = r"C:\Users\USUARIO\Desktop\fct\FIREWALL\cloudguardian-deploy\deploy\caddy.json"
            
            # Comprobar si existe
            if not os.path.exists(caddy_path):
                self.stdout.write(self.style.ERROR('No se encontró el archivo caddy.json'))
                return

            # Carpeta donde guardar los backups
            backup_folder = os.path.join(os.path.dirname(caddy_path), "backups")
            os.makedirs(backup_folder, exist_ok=True)

            # Nombre del backup con timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = os.path.join(backup_folder, f"caddy_backup_{timestamp}.json")

            # Copiar archivo
            shutil.copy2(caddy_path, backup_path)

            self.stdout.write(self.style.SUCCESS(f"Backup creado: {backup_path}"))
        
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error creando el backup: {e}"))
