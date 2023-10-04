from django.db import models
from django.contrib.auth.models import User
from django.db.models import Count, F


class PCAPFile(models.Model):
    name = models.CharField(max_length=255)
    file = models.FileField(upload_to="pcap_files/")
    file_type = models.CharField(max_length=20, blank=True, null=True)
    size = models.CharField(max_length=20, blank=True, null=True)
    date_uploaded = models.DateTimeField(auto_now_add=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)

    def packets(self):
        return NetworkPacket.objects.filter(pcap_file=self)

    def packets_grouped_by_ip(self):
        """
        Retrieve packets grouped by IP address.
        Returns a dictionary where keys are IP addresses and values are lists of packets for each IP.
        """
        grouped_packets = {}

        packets = NetworkPacket.objects.filter(pcap_file=self)

        for packet in packets:
            ip_address = packet.ip_address
            if ip_address not in grouped_packets:
                grouped_packets[ip_address] = []
            grouped_packets[ip_address].append(packet)

        return grouped_packets

    def is_xss_total(self):
        return NetworkPacket.objects.filter(is_xss=True, pcap_file=self).count()

    def is_dos_total(self):
        return NetworkPacket.objects.filter(is_dos=True, pcap_file=self).count()

    def is_brute_total(self):
        return NetworkPacket.objects.filter(is_brute_force=True, pcap_file=self).count()

    def is_sql_total(self):
        return NetworkPacket.objects.filter(
            is_sql_injection=True, pcap_file=self
        ).count()

    def __str__(self):
        return self.name

    @classmethod
    def get_top_files(cls, owner=None):
        # Create a base queryset
        queryset = cls.objects

        # Apply owner filter if provided
        if owner:
            queryset = queryset.filter(owner=owner)

        # Annotate counts for each type of incident
        files = queryset.annotate(
            xss_count=Count("networkpacket", filter=F("networkpacket__is_xss")),
            dos_count=Count("networkpacket", filter=F("networkpacket__is_dos")),
            brute_force_count=Count(
                "networkpacket", filter=F("networkpacket__is_brute_force")
            ),
        ).order_by(-(F("xss_count") + F("dos_count") + F("brute_force_count")))[:5]

        return files


class NetworkPacket(models.Model):
    # Basic packet information
    timestamp = models.DateTimeField()
    ip_address = models.GenericIPAddressField()
    dst_ip_address = models.GenericIPAddressField()
    source_port = models.PositiveIntegerField()
    port = models.PositiveIntegerField()
    protocol = models.CharField(max_length=10)

    # HTTP data (if available)
    request_method = models.CharField(max_length=10, null=True, blank=True)
    request_uri = models.TextField(null=True, blank=True)
    host = models.CharField(max_length=255, null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    referer = models.TextField(null=True, blank=True)
    response_code = models.PositiveIntegerField(null=True, blank=True)
    response_version = models.CharField(max_length=10, null=True, blank=True)

    # DNS data (if available)
    dns_info = models.TextField(null=True, blank=True)

    # Other packet information
    other_info = models.TextField(null=True, blank=True)

    # Owner and PCAP file association
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    pcap_file = models.ForeignKey(
        PCAPFile, on_delete=models.CASCADE, blank=True, null=True
    )

    # Analysis booleans
    is_brute_force = models.BooleanField(default=False)
    is_dos = models.BooleanField(default=False)
    is_sql_injection = models.BooleanField(default=False)
    is_xss = models.BooleanField(default=False)

    date_uploaded = models.DateTimeField(auto_now_add=True)
    date_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Packet at {self.timestamp} - IP: {self.ip_address}, Port: {self.port}, Protocol: {self.protocol}"
