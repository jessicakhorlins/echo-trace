# Generated by Django 4.2.5 on 2023-10-18 12:14

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0006_remove_networkpacket_task_id_pcapfile_task_id"),
    ]

    operations = [
        migrations.AddField(
            model_name="pcapfile",
            name="process_status",
            field=models.BooleanField(default=False),
        ),
    ]
