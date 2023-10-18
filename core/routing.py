from django.urls import path

from . import consumers

websocket_urlpatterns = [
    path("ws/log/<log_name>/", consumers.ChatConsumer.as_asgi()),
]