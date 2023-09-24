from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import NetworkPacket, PCAPFile
import pyshark
from django.contrib.auth.decorators import login_required
from decimal import Decimal
from datetime import datetime  # Import datetime module
from django.utils.timezone import make_aware
from .req import get_ip_info
from .utils import detect_xss, detect_sql_injection, detect_dos, detect_brute_force
from django.db.models import Q
from silk.profiling.profiler import silk_profile
from django.core.paginator import Paginator


@login_required
def search(request):
    user = request.user
    template = "search.html"
    context = {
        "user": user,
    }
    return render(request, template, context)


@login_required
def advanced_search(request):
    import time

    start_time = time.time()

    user = request.user
    category = request.GET["category"]
    prop = request.GET["property"]
    cond = request.GET["condition"]
    match_value = request.GET["match_value"]

    print(category, prop, cond, match_value)

    query = Q()

    if category:
        # so, we're not really gonna do anything with the category, it's just for formality sake!!!
        if prop == "src_ip":
            field = "ip_address"
        elif prop == "dst_ip":
            field = "dst_ip_address"
        elif prop == "src_port":
            field = "source_port"
        elif prop == "dst_port":
            field = "port"
        elif prop == "uri":
            field = "request_uri"
        elif prop == "user_agent":
            field = "user_agent"
        elif prop == "res_code":
            field = "response_code"
        elif prop == "method":
            field = "request_method"
        elif prop == "referrer":
            field = "referer"
        else:
            # others
            print("Hello World")

        # Construct the query based on the selected condition
        if cond == "contains":
            query &= Q(**{f"{field}__contains": match_value})
        elif cond == "not_contains":
            query &= ~Q(**{f"{field}__contains": match_value})
        elif cond == "equal":
            query &= Q(**{field: match_value})
        elif cond == "not_equal":
            query &= ~Q(**{field: match_value})

    # Perform the final filtered query
    packets = NetworkPacket.objects.filter(query)
    paginator = Paginator(packets, 25)  # Show 25 contacts per page.
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    end_time = time.time()
    execution_time = end_time - start_time

    print("Execution Time:", execution_time, "seconds")

    import psutil

    # Get CPU and memory usage
    cpu_usage = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory().percent

    print("CPU Usage:", cpu_usage, "%")
    print("Memory Usage:", memory_usage, "%")

    return render(
        request,
        "search.html",
        {
            "packets": packets,
            "user": user,
            "page_obj": page_obj,
            "category": category,
            "prop": prop,
            "match_value": match_value,
            "condition": cond,
        },
    )


@silk_profile(name="Dashboard")
@login_required
def dashboard(request):
    user = request.user
    files = PCAPFile.objects.filter(owner=user)
    total_packets = NetworkPacket.objects.filter(owner=user).count()
    total_rpackets = len(
        [
            n
            for n in NetworkPacket.objects.filter(owner=user)
            if n.request_uri is not None
        ]
    )
    total_npackets = len(
        [n for n in NetworkPacket.objects.filter(owner=user) if n.request_uri is None]
    )

    is_brute_force = NetworkPacket.objects.filter(is_brute_force=True).count()
    is_dos = NetworkPacket.objects.filter(is_dos=True).count()
    is_sql_injection = NetworkPacket.objects.filter(is_sql_injection=True).count()
    is_xss = NetworkPacket.objects.filter(is_xss=True).count()

    pie = [is_brute_force, is_dos, is_sql_injection, is_xss]

    docs = PCAPFile.get_top_files(owner=user)
    series = []

    # Series for XSS
    xss_series = {"name": "XSS", "color": "#1A56DB", "data": []}
    for doc in docs:
        obj = {"x": doc.name, "y": doc.is_xss_total()}
        xss_series["data"].append(obj)
    series.append(xss_series)

    # Series for DOS
    dos_series = {"name": "DOS", "color": "#FDBA8C", "data": []}
    for doc in docs:
        obj = {"x": doc.name, "y": doc.is_dos_total()}
        dos_series["data"].append(obj)
    series.append(dos_series)

    # Series for Brute force
    brute_series = {"name": "Brute Force", "color": "#FDBC8C", "data": []}
    for doc in docs:
        obj = {"x": doc.name, "y": doc.is_brute_total()}
        brute_series["data"].append(obj)
    series.append(brute_series)

    # Series for SQL Injunction
    sql_series = {"name": "SQL Injection", "color": "#FABA8C", "data": []}
    for doc in docs:
        obj = {"x": doc.name, "y": doc.is_sql_total()}
        sql_series["data"].append(obj)
    series.append(sql_series)

    context = {
        "files": files,
        "user": user,
        "pie": pie,
        "series": series,
        "total_npackets": total_npackets,
        "total_rpackets": total_rpackets,
        "total_packets": total_packets,
    }
    template = "dashboard.html"
    return render(request, template, context)


@silk_profile(name="Uploads")
@login_required
def uploads(request):
    user = request.user
    files = PCAPFile.objects.filter(owner=user)
    context = {"files": files, "user": user}
    template = "dashboard.html"
    return render(request, template, context)


@silk_profile(name="Upload PCAP")
@login_required
def upload_pcap(request):
    user = request.user
    context = {"user": user}

    if request.method == "POST":
        pcap_file = request.FILES["pcap_file"]
        file_name = pcap_file.name
        file_type = file_name.split(".")[-1]
        file_size = Decimal(pcap_file.size / (1024 * 1024))

        p = PCAPFile.objects.create(
            file=pcap_file,
            name=file_name,
            size=file_size,
            file_type=file_type,
            owner=user,
        )
        p.save()

        return redirect("uploads")

    return render(request, "upload_pcap.html", context)


@silk_profile(name="Analyse PCAP")
@login_required
def analyse_pcap(request, file_id):
    import time
    start_time = time.time()
    
    pcap_file = PCAPFile.objects.get(id=file_id)
    cap = pyshark.FileCapture(pcap_file.file.path)
    user = request.user

    is_brute_force_selected = "brute_force" in request.GET
    is_dos_selected = "dos" in request.GET
    is_sql_injection_selected = "sql_injection" in request.GET
    is_xss_selected = "xss" in request.GET

    for packet in cap:
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

    end_time = time.time()
    execution_time = end_time - start_time

    print("Execution Time:", execution_time, "seconds")

    import psutil

    # Get CPU and memory usage
    cpu_usage = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory().percent

    print("CPU Usage:", cpu_usage, "%")
    print("Memory Usage:", memory_usage, "%")


    return redirect("packet_list", file_id=pcap_file.id)


@silk_profile(name="Packet List")
@login_required
def packet_list(request, file_id):
    pcap_file = PCAPFile.objects.get(id=file_id)
    packets = NetworkPacket.objects.filter(pcap_file=pcap_file)
    user = request.user
    return render(
        request,
        "packet_list.html",
        {"packets": packets, "pcap_file": pcap_file, "user": user},
    )


@login_required
def delete_packet(request, file_id, packet_id):
    packet = NetworkPacket.objects.get(id=packet_id)
    packet.delete()
    return redirect("file_detail", file_id=file_id)


@silk_profile(name="File Details")
@login_required
def file_detail(request, file_id):
    pcap_file = PCAPFile.objects.get(id=file_id)
    packets = NetworkPacket.objects.filter(pcap_file=pcap_file)
    user = request.user

    pie = [
        pcap_file.is_brute_total(),
        pcap_file.is_dos_total(),
        pcap_file.is_sql_total(),
        pcap_file.is_xss_total(),
    ]

    ip_addresses = [ip[0] for ip in pcap_file.packets_grouped_by_ip().items()]
    ip_info = [get_ip_info(ip) for ip in ip_addresses]

    paginator = Paginator(packets, 25)  # Show 25 contacts per page.
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    return render(
        request,
        "file_details.html",
        {
            "packets": packets,
            "page_obj": page_obj,
            "pcap_file": pcap_file,
            "user": user,
            "pie": pie,
            "ip_info": ip_info,
        },
    )


@login_required
def delete_file(request, file_id):
    pcap_file = PCAPFile.objects.get(id=file_id)
    pcap_file.file.delete()
    pcap_file.delete()
    return redirect("dashboard")


@silk_profile(name="IP Details")
def ip_details(request, file_id, ip):
    pcap_file = PCAPFile.objects.get(id=file_id)
    packets = NetworkPacket.objects.filter(pcap_file=pcap_file, ip_address=ip)
    ip_info = get_ip_info(ip)
    user = request.user

    paginator = Paginator(packets, 25)  # Show 25 contacts per page.
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    return render(
        request,
        "ip_details.html",
        {
            "packets": packets,
            "pcap_file": pcap_file,
            "user": user,
            "ip": ip,
            "ip_info": ip_info,
            "page_obj": page_obj,
        },
    )


@silk_profile(name="Search Packets")
@login_required
def search_packets(request):
    if request.method == "GET":
        keyword = request.GET.get("keyword")
        user = request.user
        if keyword:
            # Perform a search in the database based on the keyword.
            packets = NetworkPacket.objects.filter(request_uri__icontains=keyword)
            # Customize the filter based on your data and search criteria.

            paginator = Paginator(packets, 25)  # Show 25 contacts per page.
            page_number = request.GET.get("page")
            page_obj = paginator.get_page(page_number)

            return render(
                request,
                "search_results.html",
                {
                    "packets": packets,
                    "keyword": keyword,
                    "user": user,
                    "page_obj": page_obj,
                },
            )

    return HttpResponse("No results found.")  # Handle no results case.
