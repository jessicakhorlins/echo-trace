from django.urls import path
from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("upload/", views.upload_pcap, name="upload_pcap"),
    path("uploads/", views.uploads, name="uploads"),
    path("file/<file_id>/<ip>/", views.ip_details, name="ip_details"),
    path("file/<file_id>/", views.file_detail, name="file_detail"),
    path("delete-file/<file_id>/", views.delete_file, name="delete_file"),
    path("analyse_pcap/<file_id>/", views.analyse_pcap, name="analyse_pcap"),
    path("packets/<file_id>/", views.packet_list, name="packet_list"),
    path(
        "delete-packet/<file_id>/<packet_id>/",
        views.delete_packet,
        name="delete_packet",
    ),
    path("results/", views.search_packets, name="search_packets"),
    path("search/", views.search, name="search"),
    path("advanced_search/", views.advanced_search, name="advanced_search"),
]
