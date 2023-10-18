from time import sleep
from celery import shared_task
import pyshark
from django.http import JsonResponse
from .models import NetworkPacket, PCAPFile
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.contrib.auth.models import User
from django.utils.timezone import make_aware
from .utils import detect_xss, detect_sql_injection, detect_dos, detect_brute_force



@shared_task()
def analyse_pcap_task(file_id, user, is_dos_selected, is_sql_injection_selected, is_xss_selected, is_brute_force_selected):
    from time import gmtime, strftime

    channel_layer = get_channel_layer()
    log_group = "log_%s" % str(file_id)
    
    pcap_file = PCAPFile.objects.get(id=file_id)
    cap = pyshark.FileCapture(pcap_file.file.path)
    user = User.objects.get(id=user)

    packets_len = 100000
    
    base_perc = packets_len / 100

    pcap_file.process_status = False
    pcap_file.save()

    for i, packet in zip(range(packets_len), cap):   
        if "IP" in packet:
            # Convert packet.sniff_time to a valid datetime
            timestamp = packet.sniff_time
            timestamp = make_aware(timestamp)

        if "http" in packet:
            http = packet.http
            ip = packet.ip

            # Extract relevant HTTP information
            request_method = (
                http.request_method if hasattr(http, "request_method") else "N/A"
            )
            request_uri = (
                http.request_full_uri if hasattr(http, "request_full_uri") else "N/A"
            )
            request_line = http.request_line if hasattr(http, "request_line") else "N/A"
            host = http.host if hasattr(http, "host") else "N/A"
            user_agent = http.user_agent if hasattr(http, "user_agent") else "N/A"
            referer = http.referer if hasattr(http, "referer") else "N/A"
            response_code = (
                http.response_code if hasattr(http, "response_code") else 000
            )
            response_version = (
                http.response_version if hasattr(http, "response_version") else "N/A"
            )
            request_date = http.date if hasattr(http, "date") else "N/A"
            server = http.server if hasattr(http, "server") else "N/A"

            ip_address = ip.addr if hasattr(ip, "addr") else "0.0.0.0"
            dst_ip_address = ip.dst_host if hasattr(ip, "dst_host") else "0.0.0.0"
            source_port = (
                packet[packet.transport_layer].srcport
                if hasattr(packet[packet.transport_layer], "srcport")
                else 0
            )
            port = (
                packet[packet.transport_layer].dstport
                if hasattr(packet[packet.transport_layer], "dstport")
                else 0
            )
            protocol = (
                packet.transport_layer
                if hasattr(packet, "transport_layer")
                else "Unknown"
            )

            try:
                dns_info = packet.dns.qry_name
            except:
                dns_info = "N/A"

            network_packet = NetworkPacket.objects.create(
                timestamp=timestamp,
                ip_address=ip_address,
                dst_ip_address=dst_ip_address,
                source_port=source_port,
                port=port,
                protocol=protocol,
                request_method=request_method,
                request_uri=request_uri,
                host=host,
                user_agent=user_agent,
                referer=referer,
                response_code=response_code,
                response_version=response_version,
                dns_info=dns_info,
                owner=user,
                pcap_file=pcap_file,
            )
            network_packet.save()

            print(request_uri)

        tt = strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())

        perc = i / base_perc
        async_to_sync(channel_layer.group_send)(log_group, {"type": "log_message", "message": {"status": f"Analysing packet {i}", "time": tt, "perc": perc}})
    

    cap.close()

    for packet in NetworkPacket.objects.filter(pcap_file=pcap_file):
        if packet.request_uri:
            if is_xss_selected:
                if detect_xss(packet.request_uri):
                    packet.is_xss = True
                    packet.save()

            if is_sql_injection_selected:
                if detect_sql_injection(packet.request_uri):
                    packet.is_sql_injection = True
                    packet.save()

            if is_brute_force_selected:
                if detect_brute_force(packet.request_uri, max_attempts=5):
                    packet.is_brute_force = True
                    packet.save()

        if is_dos_selected:
            if detect_dos(packet.ip_address, packet.dst_ip_address):
                packet.is_dos = True
                packet.save()
    
    pcap_file.process_status = True
    pcap_file.save()
