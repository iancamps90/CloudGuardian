# Generated by Django 5.2.1 on 2025-05-22 16:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cloudguardian', '0002_rename_usercaddyconfig_userjson'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userjson',
            name='json_data',
            field=models.JSONField(default=dict),
        ),
    ]
