from django.contrib import admin
from .models import NetworkPacket, PCAPFile

admin.site.register(NetworkPacket)
admin.site.register(PCAPFile)
