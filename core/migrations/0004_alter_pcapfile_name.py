# Generated by Django 4.2.5 on 2023-10-04 19:45

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0003_rename_http_request_networkpacket_request_uri_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="pcapfile",
            name="name",
            field=models.CharField(max_length=255),
        ),
    ]
