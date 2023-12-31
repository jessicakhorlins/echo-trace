# Generated by Django 4.2.4 on 2023-09-16 15:42

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="networkpacket",
            name="is_brute_force",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="networkpacket",
            name="is_dos",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="networkpacket",
            name="is_sql_injection",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="networkpacket",
            name="is_xss",
            field=models.BooleanField(default=False),
        ),
    ]
