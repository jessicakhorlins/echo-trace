@login_required
def analyse_pcap(request, file_id):
    pcap_file = PCAPFile.objects.get(id=file_id)
    cap = pyshark.FileCapture(pcap_file.file.path)
    user = request.user

    is_brute_force_selected = "brute_force" in request.GET
    is_dos_selected = "dos" in request.GET
    is_sql_injection_selected = "sql_injection" in request.GET
    is_xss_selected = "xss" in request.GET

    for packet in cap:
        # Extract and save relevant data to the database (e.g., NetworkPacket model).
        if "IP" in packet:
            # Convert packet.sniff_time to a valid datetime
            timestamp = packet.sniff_time
            timestamp = make_aware(timestamp)

            # Check if a similar packet already exists in the database
            existing_packet = NetworkPacket.objects.filter(
                Q(ip_address=packet.ip.src)
                & Q(dst_ip_address=packet.ip.dst)
                & Q(port=packet[packet.transport_layer].srcport)
                & Q(protocol=packet.transport_layer)
                & Q(timestamp=timestamp)
                & Q(pcap_file=pcap_file)
            ).first()

            if existing_packet:
                if "http" in packet:
                    try:
                        if is_xss_selected:
                            if detect_xss(packet.http.request_line):
                                existing_packet.is_xss = True
                                existing_packet.save()

                        if is_sql_injection_selected:
                            if detect_sql_injection(packet.http.request_line):
                                existing_packet.is_sql_injection = True
                                existing_packet.save()
                    except Exception as e:
                        print(e)

            if not existing_packet:
                network_packet = NetworkPacket(
                    ip_address=packet.ip.src,
                    dst_ip_address=packet.ip.dst,
                    port=packet[packet.transport_layer].srcport,
                    protocol=packet.transport_layer,
                    timestamp=timestamp,
                    owner=user,
                    pcap_file=pcap_file,
                    # Add other fields as needed
                )

                if "dns" in packet:
                    network_packet.dns_info = packet.dns.qry_name
                    network_packet.save()

                if "http" in packet:
                    try:
                        network_packet.http_request = packet.http.request_line
                        network_packet.save()

                        if is_xss_selected:
                            if detect_xss(packet.http.request_line):
                                network_packet.is_xss = True
                                network_packet.save()

                        if is_sql_injection_selected:
                            if detect_sql_injection(packet.http.request_line):
                                network_packet.is_sql_injection = True
                                network_packet.save()
                    except Exception as e:
                        print(e)

    # DOS and Brute force
    for packet in NetworkPacket.objects.filter(pcap_file=pcap_file):
        if packet.http_request:
            if is_brute_force_selected:
                if detect_brute_force(packet.http_request, max_attempts=5):
                    packet.is_brute_force = True
                    packet.save()

        if is_dos_selected:
            if detect_dos(packet.ip_address, packet.dst_ip_address):
                packet.is_dos = True
                packet.save()

    return redirect("packet_list", file_id=pcap_file.id)
